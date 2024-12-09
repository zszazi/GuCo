#!/bin/bash

# Exit on error
set -e

# Variables
SERVICE="guardian-of-containers"
NAMESPACE="guardian-of-containers"
DAYS_VALID=365
CA_KEY="ca.key"
CA_CERT="ca.crt"
TLS_KEY="tls.key"
TLS_CSR="tls.csr"
TLS_CERT="tls.crt"
SECRET_NAME="tls"

# Generate CA key and certificate
echo "Generating CA key and certificate..."
openssl genrsa -out $CA_KEY 2048
openssl req -new -x509 -days $DAYS_VALID -key $CA_KEY -subj "/C=CN/ST=GD/L=SZ/O=Acme, Inc./CN=Acme Root CA" -out $CA_CERT

# Generate TLS key and CSR
echo "Generating TLS key and CSR..."
openssl req -newkey rsa:2048 -nodes -keyout $TLS_KEY -subj "/C=CN/ST=GD/L=SZ/O=Acme, Inc./CN=$SERVICE.$NAMESPACE.svc.cluster.local" -out $TLS_CSR

# Generate TLS certificate signed by the CA
echo "Generating TLS certificate..."
openssl x509 -req -extfile <(printf "subjectAltName=DNS:$SERVICE.$NAMESPACE.svc.cluster.local,DNS:$SERVICE.$NAMESPACE.svc.cluster,DNS:$SERVICE.$NAMESPACE.svc,DNS:$SERVICE.$NAMESPACE,DNS:$SERVICE") -days $DAYS_VALID -in $TLS_CSR -CA $CA_CERT -CAkey $CA_KEY -CAcreateserial -out $TLS_CERT

#create ns
echo "Create Namespace"
kubectl create ns $NAMESPACE

# Create Kubernetes secret
echo "Creating Kubernetes secret..."
kubectl create secret tls $SECRET_NAME --cert=$TLS_CERT --key=$TLS_KEY -n $NAMESPACE

# Cleanup files
#echo "Cleaning up generated files..."
#rm -f $CA_KEY $CA_CERT $TLS_KEY $TLS_CSR $TLS_CERT ca.srl

echo "All done! TLS secret '$SECRET_NAME' created in namespace '$NAMESPACE'."
