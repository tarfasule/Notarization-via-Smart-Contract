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
