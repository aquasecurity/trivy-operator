# Clear the screen for a clean output
Clear-Host

# --- 1. DEFINE THE KUBERNETES JOB IN YAML ---
# Using a PowerShell "here-string" to hold the multi-line YAML content.
$jobYaml = @"
apiVersion: batch/v1
kind: Job
metadata:
  name: powershell-job-catcher
  namespace: trivy-system
spec:
  template:
    spec:
      containers:
      - name: nginx-container
        image: nginx:1.20.0
        command: ["/bin/sh", "-c", "echo 'Hello from my first Kubernetes Job!' && sleep 10 && echo 'Job finished.'"]
      restartPolicy: Never
  backoffLimit: 4
  ttlSecondsAfterFinished: 100 # Cleans up the job 100 seconds after it's done
"@

# --- 2. APPLY THE JOB TO THE CLUSTER ---
$jobYaml | kubectl apply -f -


# ---- 3. Catch Job in jobFile.yaml ----
$Job | kubectl get job powershell-job-catcher -o yaml > jobFile.yaml

