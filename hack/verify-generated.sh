FILE_DIFF=$(git ls-files -o --exclude-standard)

if [ "$FILE_DIFF" != "" ]; then
  echo "Found untracked generated files:"
  echo $FILE_DIFF
  exit 1
fi

git diff --exit-code
