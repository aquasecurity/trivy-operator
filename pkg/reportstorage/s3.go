package reportstorage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// defaultRegion is used when neither the options nor the AWS environment set a region.
// S3-compatible servers such as MinIO accept it.
const defaultRegion = "us-east-1"

// S3Options configures an S3 or S3-compatible bucket.
// Credentials come from the default AWS chain: environment, shared config, IRSA or Pod Identity.
type S3Options struct {
	Bucket string
	Prefix string

	// Endpoint overrides the AWS endpoint, for example "https://minio.minio:9000".
	Endpoint string
	Region   string

	// UsePathStyle addresses the bucket as endpoint/bucket instead of bucket.endpoint.
	// Most self-hosted S3-compatible servers need it.
	UsePathStyle bool
}

type s3Store struct {
	client *s3.Client
	bucket string
	prefix string
}

// NewS3 returns a Store that uploads reports to a bucket.
// It checks that the bucket is reachable, so misconfiguration fails at startup.
func NewS3(ctx context.Context, opts S3Options) (Store, error) {
	if opts.Bucket == "" {
		return nil, errors.New("alternate report storage S3 bucket must be set")
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	if opts.Region != "" {
		cfg.Region = opts.Region
	}
	if cfg.Region == "" {
		cfg.Region = defaultRegion
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = opts.UsePathStyle
		if opts.Endpoint != "" {
			o.BaseEndpoint = aws.String(opts.Endpoint)

			// Many S3-compatible servers reject the default CRC checksums.
			o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
			o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
		}
	})

	if _, err := client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(opts.Bucket)}); err != nil {
		return nil, fmt.Errorf("failed to access S3 bucket %q: %w", opts.Bucket, err)
	}

	return &s3Store{client: client, bucket: opts.Bucket, prefix: opts.Prefix}, nil
}

// specHashMetadata is stored as the x-amz-meta-spec-hash header.
const specHashMetadata = "spec-hash"

func (s *s3Store) Put(ctx context.Context, key string, report any, meta Meta) error {
	var body bytes.Buffer
	if err := encode(&body, report); err != nil {
		return err
	}

	objectKey := path.Join(s.prefix, key)
	input := &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(objectKey),
		Body:        bytes.NewReader(body.Bytes()),
		ContentType: aws.String("application/json"),
	}
	if meta.SpecHash != "" {
		input.Metadata = map[string]string{specHashMetadata: meta.SpecHash}
	}
	if _, err := s.client.PutObject(ctx, input); err != nil {
		return fmt.Errorf("failed to upload report to s3://%s/%s: %w", s.bucket, objectKey, err)
	}
	return nil
}

// Stat reads object metadata with HeadObject, so the report body is not downloaded.
// Without s3:ListBucket, S3 answers 403 for a missing key, and Stat returns it as an error.
func (s *s3Store) Stat(ctx context.Context, key string) (Meta, bool, error) {
	objectKey := path.Join(s.prefix, key)
	out, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		if isNotFound(err) {
			return Meta{}, false, nil
		}
		return Meta{}, false, fmt.Errorf("failed to stat report s3://%s/%s: %w", s.bucket, objectKey, err)
	}

	meta := Meta{ModTime: aws.ToTime(out.LastModified)}
	for k, v := range out.Metadata {
		if strings.EqualFold(k, specHashMetadata) {
			meta.SpecHash = v
		}
	}
	return meta, true, nil
}

// isNotFound matches a 404 by type and by status code, because HEAD responses
// carry no error body and S3-compatible servers differ in what they return.
func isNotFound(err error) bool {
	var notFound *types.NotFound
	if errors.As(err, &notFound) {
		return true
	}
	var respErr *awshttp.ResponseError
	return errors.As(err, &respErr) && respErr.HTTPStatusCode() == http.StatusNotFound
}
