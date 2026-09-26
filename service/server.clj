#!/usr/bin/env bb
;; server.clj — executable entry point for the iam.guard PEP.
;;
;; The implementation lives in policy_service.clj so native unit tests can load
;; it without starting an HTTP server.  This file preserves the direct launch
;; command used by operators: bb service/server.clj
;;
;; Run:  opa run -s policy/ &          # PDP on :8181
;;       bb service/server.clj &       # PEP on :8080

(def server-file (or *file* "service/server.clj"))
(load-file (str (.getParent (java.io.File. server-file))
                "/policy_service.clj"))
((resolve 'policy-service/-main))
