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
    (asserts! (is-eq (get owner doc) tx-sender) err-owner-only)
    
    (map-set documents
      {hash: hash}
      (merge doc {owner: new-owner})
    )

    ;; (map-set document-owners
    ;;   tx-sender
    ;;   (unwrap-panic (as-max-len? 
    ;;     (filter (lambda (item) (not-hash item hash)) (get-owner-documents tx-sender))
    ;;     u100
    ;;   ))
    ;; )

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

;; (define-public (revoke-document-access (hash (buff 32)) (grantee principal))
;;   (let
;;     (
;;       (doc (unwrap! (map-get? documents {hash: hash}) err-not-found))
;;       (current-grants (get-user-permissions grantee))
;;       (filtered-grants (filter (lambda (grant) (not (is-eq (get hash grant) hash))) current-grants))
;;     )
;;     (asserts! (is-eq (get owner doc) tx-sender) err-owner-only)
    
;;     (map-delete document-permissions { hash: hash, grantee: grantee })
    
;;     (map-set permission-grants
;;       grantee
;;       (unwrap-panic (as-max-len? filtered-grants u50))
;;     )
    
;;     (ok true)
;;   )
;; )


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