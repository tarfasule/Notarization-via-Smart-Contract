;; Document Audit Trail System
;; Immutable audit logging for all document operations

(define-constant contract-owner tx-sender)
(define-constant err-audit-not-found (err u300))
(define-constant err-invalid-action-type (err u301))
(define-constant err-unauthorized-audit-access (err u302))
(define-constant err-invalid-audit-filter (err u303))

;; Data variables
(define-data-var next-audit-id uint u1)
(define-data-var total-audit-entries uint u0)

;; Maps for audit trail storage
(define-map audit-entries
    uint
    {
        document-hash: (buff 32),
        action-type: (string-ascii 20),
        actor: principal,
        timestamp: uint,
        block-height: uint,
        metadata: (optional (string-ascii 200)),
        previous-owner: (optional principal),
        new-owner: (optional principal),
        status-change: (optional (string-ascii 15))
    }
)

(define-map document-audit-history
    (buff 32)
    {
        entry-count: uint,
        first-entry-id: uint,
        last-entry-id: uint,
        created-at: uint,
        last-activity: uint
    }
)

(define-map user-audit-activity
    principal
    {
        total-actions: uint,
        first-action-id: uint,
        last-action-id: uint,
        documents-created: uint,
        documents-transferred: uint,
        documents-revoked: uint,
        verifications-performed: uint
    }
)

(define-map audit-entry-sequences
    (buff 32)
    (list 100 uint)
)

;; Read-only functions
(define-read-only (get-audit-entry (entry-id uint))
    (match (map-get? audit-entries entry-id)
        entry-data (ok entry-data)
        (err err-audit-not-found)
    )
)

(define-read-only (get-document-audit-summary (document-hash (buff 32)))
    (match (map-get? document-audit-history document-hash)
        summary-data (ok summary-data)
        (ok {
            entry-count: u0,
            first-entry-id: u0,
            last-entry-id: u0,
            created-at: u0,
            last-activity: u0
        })
    )
)

(define-read-only (get-user-audit-activity (user principal))
    (match (map-get? user-audit-activity user)
        activity-data (ok activity-data)
        (ok {
            total-actions: u0,
            first-action-id: u0,
            last-action-id: u0,
            documents-created: u0,
            documents-transferred: u0,
            documents-revoked: u0,
            verifications-performed: u0
        })
    )
)

(define-read-only (get-document-audit-entries (document-hash (buff 32)))
    (default-to (list) (map-get? audit-entry-sequences document-hash))
)

(define-read-only (get-audit-statistics)
    (ok {
        total-entries: (var-get total-audit-entries),
        next-entry-id: (var-get next-audit-id)
    })
)

;; Private functions
(define-private (is-valid-action-type (action (string-ascii 20)))
    (or 
        (is-eq action "notarized")
        (or
            (is-eq action "transferred")
            (or
                (is-eq action "revoked")
                (or
                    (is-eq action "verified")
                    (or
                        (is-eq action "permission-granted")
                        (or
                            (is-eq action "permission-revoked")
                            (or
                                (is-eq action "version-created")
                                (is-eq action "expired")
                            )
                        )
                    )
                )
            )
        )
    )
)

(define-private (log-audit-entry 
    (document-hash (buff 32))
    (action-type (string-ascii 20))
    (actor principal)
    (metadata (optional (string-ascii 200)))
    (previous-owner (optional principal))
    (new-owner (optional principal))
    (status-change (optional (string-ascii 15))))
    
    (let ((entry-id (var-get next-audit-id))
          (current-timestamp stacks-block-height))
        
        ;; Create audit entry
        (map-set audit-entries entry-id {
            document-hash: document-hash,
            action-type: action-type,
            actor: actor,
            timestamp: current-timestamp,
            block-height: current-timestamp,
            metadata: metadata,
            previous-owner: previous-owner,
            new-owner: new-owner,
            status-change: status-change
        })
        
        ;; Update document audit history
        (let ((current-history (unwrap-panic (get-document-audit-summary document-hash))))
            (map-set document-audit-history document-hash {
                entry-count: (+ (get entry-count current-history) u1),
                first-entry-id: (if (is-eq (get entry-count current-history) u0)
                                   entry-id
                                   (get first-entry-id current-history)),
                last-entry-id: entry-id,
                created-at: (if (is-eq (get entry-count current-history) u0)
                              current-timestamp
                              (get created-at current-history)),
                last-activity: current-timestamp
            })
        )
        
        ;; Update user audit activity
        (let ((current-activity (unwrap-panic (get-user-audit-activity actor))))
            (map-set user-audit-activity actor {
                total-actions: (+ (get total-actions current-activity) u1),
                first-action-id: (if (is-eq (get total-actions current-activity) u0)
                                   entry-id
                                   (get first-action-id current-activity)),
                last-action-id: entry-id,
                documents-created: (+ (get documents-created current-activity)
                                    (if (is-eq action-type "notarized") u1 u0)),
                documents-transferred: (+ (get documents-transferred current-activity)
                                        (if (is-eq action-type "transferred") u1 u0)),
                documents-revoked: (+ (get documents-revoked current-activity)
                                    (if (is-eq action-type "revoked") u1 u0)),
                verifications-performed: (+ (get verifications-performed current-activity)
                                          (if (is-eq action-type "verified") u1 u0))
            })
        )
        
        ;; Update entry sequence for document
        (let ((current-sequence (get-document-audit-entries document-hash)))
            (map-set audit-entry-sequences document-hash
                (unwrap-panic (as-max-len? (append current-sequence entry-id) u100))
            )
        )
        
        ;; Update counters
        (var-set next-audit-id (+ entry-id u1))
        (var-set total-audit-entries (+ (var-get total-audit-entries) u1))
        
        entry-id
    )
)

;; Public audit logging functions
(define-public (log-document-notarized 
    (document-hash (buff 32))
    (owner principal)
    (title (string-ascii 64)))
    
    (begin
        (asserts! (is-valid-action-type "notarized") (err err-invalid-action-type))
        (ok (log-audit-entry 
            document-hash 
            "notarized" 
            owner 
            (some title) 
            none 
            (some owner) 
            (some "ACTIVE")))
    )
)

(define-public (log-document-transferred 
    (document-hash (buff 32))
    (previous-owner principal)
    (new-owner principal))
    
    (begin
        (asserts! (is-valid-action-type "transferred") (err err-invalid-action-type))
        (ok (log-audit-entry 
            document-hash 
            "transferred" 
            tx-sender 
            none 
            (some previous-owner) 
            (some new-owner) 
            none))
    )
)

(define-public (log-document-revoked 
    (document-hash (buff 32))
    (owner principal)
    (reason (optional (string-ascii 200))))
    
    (begin
        (asserts! (is-valid-action-type "revoked") (err err-invalid-action-type))
        (ok (log-audit-entry 
            document-hash 
            "revoked" 
            owner 
            reason 
            none 
            none 
            (some "REVOKED")))
    )
)

(define-public (log-document-verified 
    (document-hash (buff 32))
    (authority principal))
    
    (begin
        (asserts! (is-valid-action-type "verified") (err err-invalid-action-type))
        (ok (log-audit-entry 
            document-hash 
            "verified" 
            authority 
            none 
            none 
            none 
            (some "VERIFIED")))
    )
)

(define-public (log-permission-granted 
    (document-hash (buff 32))
    (granter principal)
    (grantee principal)
    (permission-type (string-ascii 200)))
    
    (begin
        (asserts! (is-valid-action-type "permission-granted") (err err-invalid-action-type))
        (ok (log-audit-entry 
            document-hash 
            "permission-granted" 
            granter 
            (some permission-type) 
            none 
            (some grantee) 
            none))
    )
)

(define-public (log-version-created 
    (document-hash (buff 32))
    (author principal)
    (version-number uint))
    
    (begin
        (asserts! (is-valid-action-type "version-created") (err err-invalid-action-type))
        (let ((version-info (unwrap-panic (to-ascii version-number))))
            (ok (log-audit-entry 
                document-hash 
                "version-created" 
                author 
                (some (unwrap-panic (as-max-len? version-info u200))) 
                none 
                none 
                none))
        )
    )
)

;; Public query functions
(define-public (get-document-audit-trail (document-hash (buff 32)) (limit uint))
    (let ((entry-ids (get-document-audit-entries document-hash))
          (actual-limit (if (<= limit u20) limit u20)))
        (ok {
            document-hash: document-hash,
            total-entries: (len entry-ids),
            entries: (slice? entry-ids u0 actual-limit)
        })
    )
)

(define-public (get-user-audit-summary (user principal))
    (let ((activity-data (unwrap-panic (get-user-audit-activity user))))
        (ok {
            user: user,
            summary: activity-data
        })
    )
)

;; Helper function to convert uint to ascii for metadata
(define-private (to-ascii (value uint))
    (if (is-eq value u0) (ok "0")
        (if (is-eq value u1) (ok "1")
            (if (is-eq value u2) (ok "2")
                (if (is-eq value u3) (ok "3")
                    (if (is-eq value u4) (ok "4")
                        (if (is-eq value u5) (ok "5")
                            (if (is-eq value u6) (ok "6")
                                (if (is-eq value u7) (ok "7")
                                    (if (is-eq value u8) (ok "8")
                                        (if (is-eq value u9) (ok "9")
                                            (ok "N")
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            )
        )
    )
)
