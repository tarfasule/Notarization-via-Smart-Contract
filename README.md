# Notarization Smart Contract

A Stacks blockchain smart contract for immutable document notarization. Store document hashes with timestamps and ownership information on-chain.

## Features

- Notarize documents by storing their hash with timestamp
- View document notarization details
- Transfer document ownership
- Revoke documents
- Track document ownership history
- List all documents by owner

## Contract Functions

### Notarize Document
```clarity
(notarize-document hash title description)
```
Stores a new document hash with metadata and timestamp

### Get Document
```clarity
(get-document hash)
```
Retrieves document details by hash

### Get Owner Documents
```clarity
(get-owner-documents owner)
```
Lists all documents owned by an address

### Transfer Ownership
```clarity
(transfer-ownership hash new-owner)
```
Transfers document ownership to new address

### Revoke Document
```clarity
(revoke-document hash)
```
Marks a document as revoked

## Usage

1. Calculate document hash (SHA256)
2. Call notarize-document with hash and metadata
3. Document is permanently stored with current block timestamp
4. Retrieve using get-document function
5. Manage ownership with transfer-ownership
6. Revoke if needed with revoke-document

## Error Codes

- u100: Owner only operation
- u101: Document already notarized
- u102: Invalid hash format
- u103: Document not found
```
