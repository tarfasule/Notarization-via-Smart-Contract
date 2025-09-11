(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u100))
(define-constant err-already-notarized (err u101))
(define-constant err-invalid-hash (err u102))
(define-constant err-not-found (err u103))

(define-data-var total-documents uint u0)

(define-map documents
  { hash: (buff 32) }
  {
    owner: principal,
    timestamp: uint,
    title: (string-ascii 64),
    description: (string-ascii 256),
    status: (string-ascii 12)
  }
)

(define-map document-owners
  principal
  (list 100 (buff 32))
)

(define-read-only (get-document (hash (buff 32)))
  (match (map-get? documents {hash: hash})
    entry (ok entry)
    (err err-not-found)
  )
)

(define-read-only (get-owner-documents (owner principal))
  (match (map-get? document-owners owner)
    entry entry
    (list)
  )
)

(define-read-only (get-total-documents)
  (var-get total-documents)
)

(define-public (notarize-document 
    (hash (buff 32))
    (title (string-ascii 64))
    (description (string-ascii 256)))
  (let
    (
      (timestamp (unwrap-panic (get-stacks-block-info? time u0)))
    )
    (asserts! (is-none (map-get? documents {hash: hash})) err-already-notarized)
    (asserts! (is-eq (len hash) u32) err-invalid-hash)
    
    (map-set documents
      {hash: hash}
      {
        owner: tx-sender,
        timestamp: timestamp,
        title: title,
        description: description,
        status: "ACTIVE"
      }
    )

    (map-set document-owners
      tx-sender
      (unwrap-panic (as-max-len? 
        (append (get-owner-documents tx-sender) hash)
        u100
      ))
    )

    (var-set total-documents (+ (var-get total-documents) u1))
    (ok hash)
  )
)
(define-public (revoke-document (hash (buff 32)))
  (let
    (
      (doc (unwrap! (map-get? documents {hash: hash}) err-not-found))
    )
    (asserts! (is-eq (get owner doc) tx-sender) err-owner-only)
    (map-set documents
      {hash: hash}
      (merge doc {status: "REVOKED"})
    )
    (ok true)
  )
)

(define-public (transfer-ownership (hash (buff 32)) (new-owner principal))
  (let
    (
      (doc (unwrap! (map-get? documents {hash: hash}) err-not-found))
    )
    (begin
      (asserts! (is-eq (get owner doc) tx-sender) err-owner-only)
      
      (map-set documents
        {hash: hash}
        (merge doc {owner: new-owner})
      )

      (map-set document-owners
        new-owner
        (unwrap-panic (as-max-len? 
          (append (get-owner-documents new-owner) hash)
          u100
        ))
      )
      
      (ok true)
    )
  )
)

(define-private (not-hash (item (buff 32)) (hash (buff 32)))
  (not (is-eq item hash))
)


(define-constant err-not-authority (err u104))

(define-map trusted-authorities
  principal 
  bool
)

(define-public (add-authority (authority principal))
  (begin
    (asserts! (is-eq tx-sender contract-owner) err-owner-only)
    (map-set trusted-authorities authority true)
    (ok true)
  )
)

(define-public (verify-document (hash (buff 32)))
  (let
    (
      (doc (unwrap! (map-get? documents {hash: hash}) err-not-found))
      (is-authority (default-to false (map-get? trusted-authorities tx-sender)))
    )
    (asserts! is-authority err-not-authority)
    (map-set documents
      {hash: hash}
      (merge doc {status: "VERIFIED"})
    )
    (ok true)
  )
)


(define-constant err-expired (err u105))

(define-map document-expiry
  (buff 32)
  uint
)

(define-public (set-document-expiry (hash (buff 32)) (expiry-height uint))
  (let
    (
      (doc (unwrap! (map-get? documents {hash: hash}) err-not-found))
    )
    (asserts! (is-eq (get owner doc) tx-sender) err-owner-only)
    (map-set document-expiry hash expiry-height)
    (ok true)
  )
)

(define-read-only (is-document-valid (hash (buff 32)))
  (let
    (
      (expiry (map-get? document-expiry hash))
      (current-height stacks-block-height)
    )
    (if (and (is-some expiry) (> (unwrap! expiry err-not-found) current-height))
      (ok true)
      (ok false)
    )
  )
)

(define-constant err-access-denied (err u106))
(define-constant err-invalid-permission (err u107))

(define-map document-permissions
  { hash: (buff 32), grantee: principal }
  { read: bool, write: bool, verify: bool }
)

(define-map permission-grants
  principal
  (list 50 { hash: (buff 32), permissions: { read: bool, write: bool, verify: bool } })
)

(define-read-only (get-document-permissions (hash (buff 32)) (grantee principal))
  (default-to 
    { read: false, write: false, verify: false }
    (map-get? document-permissions { hash: hash, grantee: grantee })
  )
)

(define-read-only (get-user-permissions (user principal))
  (default-to 
    (list)
    (map-get? permission-grants user)
  )
)

(define-read-only (has-read-access (hash (buff 32)) (user principal))
  (let
    (
      (doc (unwrap! (map-get? documents {hash: hash}) (ok false)))
      (perms (get-document-permissions hash user))
    )
    (ok (or 
      (is-eq (get owner doc) user)
      (get read perms)
    ))
  )
)

(define-read-only (has-write-access (hash (buff 32)) (user principal))
  (let
    (
      (doc (unwrap! (map-get? documents {hash: hash}) (ok false)))
      (perms (get-document-permissions hash user))
    )
    (ok (or 
      (is-eq (get owner doc) user)
      (get write perms)
    ))
  )
)

(define-read-only (has-verify-access (hash (buff 32)) (user principal))
  (let
    (
      (doc (unwrap! (map-get? documents {hash: hash}) (ok false)))
      (perms (get-document-permissions hash user))
      (is-authority (default-to false (map-get? trusted-authorities user)))
    )
    (ok (or 
      (is-eq (get owner doc) user)
      (get verify perms)
      is-authority
    ))
  )
)

(define-public (grant-document-access 
    (hash (buff 32)) 
    (grantee principal) 
    (read-perm bool) 
    (write-perm bool) 
    (verify-perm bool))
  (let
    (
      (doc (unwrap! (map-get? documents {hash: hash}) err-not-found))
      (new-perms { read: read-perm, write: write-perm, verify: verify-perm })
      (current-grants (get-user-permissions grantee))
      (new-grant { hash: hash, permissions: new-perms })
    )
    (asserts! (is-eq (get owner doc) tx-sender) err-owner-only)
    
    (map-set document-permissions
      { hash: hash, grantee: grantee }
      new-perms
    )
    
    (map-set permission-grants
      grantee
      (unwrap-panic (as-max-len?
        (append current-grants new-grant)
        u50
      ))
    )
    
    (ok true)
  )
)

(define-public (revoke-document-access (hash (buff 32)) (grantee principal))
  (let
    (
      (doc (unwrap! (map-get? documents {hash: hash}) err-not-found))
    )
    (begin
      (asserts! (is-eq (get owner doc) tx-sender) err-owner-only)
      
      (map-delete document-permissions { hash: hash, grantee: grantee })
      
      (ok true)
    )
  )
)


(define-public (revoke-document-with-access (hash (buff 32)))
  (let
    (
      (has-access (unwrap! (has-write-access hash tx-sender) err-access-denied))
    )
    (asserts! has-access err-access-denied)
    (revoke-document hash)
  )
)

(define-public (verify-document-with-access (hash (buff 32)))
  (let
    (
      (has-access (unwrap! (has-verify-access hash tx-sender) err-access-denied))
    )
    (asserts! has-access err-access-denied)
    (verify-document hash)
  )
)

(define-constant err-batch-empty (err u108))
(define-constant err-batch-limit (err u109))
(define-constant max-batch-size u10)

(define-public (batch-notarize-documents 
    (doc-list (list 10 { hash: (buff 32), title: (string-ascii 64), description: (string-ascii 256) })))
  (let
    (
      (batch-size (len doc-list))
      (timestamp (unwrap-panic (get-stacks-block-info? time u0)))
    )
    (asserts! (> batch-size u0) err-batch-empty)
    (asserts! (<= batch-size max-batch-size) err-batch-limit)
    
    (ok (map batch-notarize-single doc-list))
  )
)

(define-private (batch-notarize-single (doc { hash: (buff 32), title: (string-ascii 64), description: (string-ascii 256) }))
  (let
    (
      (hash (get hash doc))
      (title (get title doc))
      (description (get description doc))
      (timestamp (unwrap-panic (get-stacks-block-info? time u0)))
    )
    (if (is-none (map-get? documents {hash: hash}))
      (begin
        (map-set documents
          {hash: hash}
          {
            owner: tx-sender,
            timestamp: timestamp,
            title: title,
            description: description,
            status: "ACTIVE"
          }
        )
        (map-set document-owners
          tx-sender
          (unwrap-panic (as-max-len? 
            (append (get-owner-documents tx-sender) hash)
            u100
          ))
        )
        (var-set total-documents (+ (var-get total-documents) u1))
        (ok hash)
      )
      (err err-already-notarized)
    )
  )
)

(define-public (batch-revoke-documents (hashes (list 10 (buff 32))))
  (let
    (
      (batch-size (len hashes))
    )
    (asserts! (> batch-size u0) err-batch-empty)
    (asserts! (<= batch-size max-batch-size) err-batch-limit)
    
    (ok (map batch-revoke-single hashes))
  )
)

(define-private (batch-revoke-single (hash (buff 32)))
  (match (map-get? documents {hash: hash})
    doc (if (is-eq (get owner doc) tx-sender)
          (begin
            (map-set documents
              {hash: hash}
              (merge doc {status: "REVOKED"})
            )
            (ok true)
          )
          (err err-owner-only)
        )
    (err err-not-found)
  )
)

(define-public (batch-verify-documents (hashes (list 10 (buff 32))))
  (let
    (
      (batch-size (len hashes))
      (is-authority (default-to false (map-get? trusted-authorities tx-sender)))
    )
    (asserts! (> batch-size u0) err-batch-empty)
    (asserts! (<= batch-size max-batch-size) err-batch-limit)
    (asserts! is-authority err-not-authority)
    
    (ok (map batch-verify-single hashes))
  )
)

(define-private (batch-verify-single (hash (buff 32)))
  (match (map-get? documents {hash: hash})
    doc (begin
          (map-set documents
            {hash: hash}
            (merge doc {status: "VERIFIED"})
          )
          (ok true)
        )
    (err err-not-found)
  )
)

(define-read-only (get-batch-status (hashes (list 10 (buff 32))))
  (map get-document-status hashes)
)

(define-private (get-document-status (hash (buff 32)))
  (match (map-get? documents {hash: hash})
    doc (ok (get status doc))
    (err err-not-found)
  )
)

;; Document Versioning System - Track document evolution with immutable history
(define-constant err-version-not-found (err u110))
(define-constant err-invalid-version (err u111))
(define-constant err-no-previous-version (err u112))
(define-constant max-change-description u200)
(define-constant max-versions-per-document u50)

;; Map to store document versions: {document-id, version} -> version-data
(define-map document-versions
  { document-id: (buff 32), version: uint }
  {
    version-hash: (buff 32),
    timestamp: uint,
    author: principal,
    change-description: (string-ascii 200),
    previous-version: (optional uint),
    is-current: bool
  }
)

;; Map to track latest version number for each document
(define-map document-version-counter
  (buff 32)
  uint
)

;; Map to store document version history as a list
(define-map document-version-history
  (buff 32)
  (list 50 uint)
)

;; Read-only function to get a specific version of a document
(define-read-only (get-document-version (document-id (buff 32)) (version uint))
  (match (map-get? document-versions { document-id: document-id, version: version })
    version-data (ok version-data)
    (err err-version-not-found)
  )
)

;; Read-only function to get the current version number for a document
(define-read-only (get-current-version-number (document-id (buff 32)))
  (default-to u0 (map-get? document-version-counter document-id))
)

;; Read-only function to get all version numbers for a document
(define-read-only (get-document-version-history (document-id (buff 32)))
  (default-to (list) (map-get? document-version-history document-id))
)

;; Read-only function to get the current version data
(define-read-only (get-current-version (document-id (buff 32)))
  (let
    (
      (current-version-num (get-current-version-number document-id))
    )
    (if (> current-version-num u0)
      (get-document-version document-id current-version-num)
      (err err-version-not-found)
    )
  )
)

;; Read-only function to compare two versions
(define-read-only (compare-versions (document-id (buff 32)) (version1 uint) (version2 uint))
  (let
    (
      (v1-data (unwrap! (get-document-version document-id version1) (err err-version-not-found)))
      (v2-data (unwrap! (get-document-version document-id version2) (err err-version-not-found)))
    )
    (ok {
      version1: {
        version: version1,
        hash: (get version-hash v1-data),
        timestamp: (get timestamp v1-data),
        author: (get author v1-data),
        description: (get change-description v1-data)
      },
      version2: {
        version: version2,
        hash: (get version-hash v2-data),
        timestamp: (get timestamp v2-data),
        author: (get author v2-data),
        description: (get change-description v2-data)
      }
    })
  )
)

;; Public function to create a new version of an existing document
(define-public (create-document-version 
    (document-id (buff 32))
    (new-version-hash (buff 32))
    (change-description (string-ascii 200)))
  (let
    (
      (doc (unwrap! (map-get? documents { hash: document-id }) err-not-found))
      (current-version-num (get-current-version-number document-id))
      (new-version-num (+ current-version-num u1))
      (timestamp (unwrap-panic (get-stacks-block-info? time u0)))
      (current-history (get-document-version-history document-id))
    )
    (begin
      ;; Only document owner can create versions
      (asserts! (is-eq (get owner doc) tx-sender) err-owner-only)
      
      ;; Validate inputs
      (asserts! (is-eq (len new-version-hash) u32) err-invalid-hash)
      (asserts! (<= (len change-description) max-change-description) err-invalid-version)
      (asserts! (<= new-version-num max-versions-per-document) err-batch-limit)
      
      ;; Mark previous version as not current if it exists
      (if (> current-version-num u0)
        (map-set document-versions
          { document-id: document-id, version: current-version-num }
          (merge 
            (unwrap-panic (map-get? document-versions { document-id: document-id, version: current-version-num }))
            { is-current: false }
          )
        )
        true
      )
      
      ;; Create new version entry
      (map-set document-versions
        { document-id: document-id, version: new-version-num }
        {
          version-hash: new-version-hash,
          timestamp: timestamp,
          author: tx-sender,
          change-description: change-description,
          previous-version: (if (> current-version-num u0) (some current-version-num) none),
          is-current: true
        }
      )
      
      ;; Update version counter
      (map-set document-version-counter document-id new-version-num)
      
      ;; Update version history
      (map-set document-version-history
        document-id
        (unwrap-panic (as-max-len?
          (append current-history new-version-num)
          u50
        ))
      )
      
      (ok { document-id: document-id, version: new-version-num, version-hash: new-version-hash })
    )
  )
)

;; Public function to initialize versioning for an existing document
(define-public (initialize-document-versioning 
    (document-id (buff 32))
    (initial-description (string-ascii 200)))
  (let
    (
      (doc (unwrap! (map-get? documents { hash: document-id }) err-not-found))
      (existing-version (get-current-version-number document-id))
      (timestamp (get timestamp doc))
    )
    (begin
      ;; Only document owner can initialize versioning
      (asserts! (is-eq (get owner doc) tx-sender) err-owner-only)
      
      ;; Check if versioning is already initialized
      (asserts! (is-eq existing-version u0) err-already-notarized)
      
      ;; Create initial version (v1) using the original document
      (map-set document-versions
        { document-id: document-id, version: u1 }
        {
          version-hash: document-id,
          timestamp: timestamp,
          author: (get owner doc),
          change-description: initial-description,
          previous-version: none,
          is-current: true
        }
      )
      
      ;; Set version counter to 1
      (map-set document-version-counter document-id u1)
      
      ;; Initialize version history
      (map-set document-version-history document-id (list u1))
      
      (ok { document-id: document-id, version: u1, initialized: true })
    )
  )
)

;; Public function to revert to a previous version (creates new version with old content)
(define-public (revert-to-version 
    (document-id (buff 32))
    (target-version uint)
    (revert-description (string-ascii 200)))
  (let
    (
      (doc (unwrap! (map-get? documents { hash: document-id }) err-not-found))
      (target-version-data (unwrap! (get-document-version document-id target-version) err-version-not-found))
      (target-hash (get version-hash target-version-data))
    )
    (begin
      ;; Only document owner can revert versions
      (asserts! (is-eq (get owner doc) tx-sender) err-owner-only)
      
      ;; Create new version with the target version's hash
      (create-document-version document-id target-hash revert-description)
    )
  )
)

;; Read-only function to get version statistics for a document
(define-read-only (get-version-statistics (document-id (buff 32)))
  (let
    (
      (total-versions (get-current-version-number document-id))
      (version-history (get-document-version-history document-id))
    )
    (ok {
      total-versions: total-versions,
      has-versioning: (> total-versions u0),
      version-history: version-history,
      latest-version: total-versions
    })
  )
)

;; Read-only function to get version chain (trace back through previous versions)
(define-read-only (get-version-chain (document-id (buff 32)) (from-version uint))
  (let
    (
      (version-data (unwrap! (get-document-version document-id from-version) (err err-version-not-found)))
      (previous-version (get previous-version version-data))
    )
    (ok {
      current-version: from-version,
      has-previous: (is-some previous-version),
      previous-version: previous-version,
      author: (get author version-data),
      timestamp: (get timestamp version-data),
      description: (get change-description version-data)
    })
  )
)



