set -e
docker build --no-cache -t bchunlimited/pyrrha:ubuntu20.04 .
docker push bchunlimited/pyrrha:ubuntu20.04
