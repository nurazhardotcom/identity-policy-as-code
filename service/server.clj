#!/usr/bin/env bb
;; server.clj — request-time enforcement (PEP) for the iam.guard policy.
;;
;; Architecture: this process is a Policy Enforcement Point (PEP). Every
;; /v1/check request is forwarded to an OPA server acting as the Policy
;; Decision Point (PDP), which evaluates the SAME Rego source the CI gate
;; uses. One policy, two enforcement points — no drift possible.
;;
;; Run:  opa run -s policy/ &          # PDP on :8181
;;       bb service/server.clj &       # PEP on :8080
;; Test: curl -s localhost:8080/v1/check -d '{"role":"x","actions":["*"],"resources":["*"]}'

(require '[babashka.http-client :as http]
         '[cheshire.core :as json]
         '[clojure.string :as str]
         '[org.httpkit.server :as srv])

(def pdp-url "http://127.0.0.1:8181/v1/data/iam/guard/deny")

(defn- normalize [body]
  "Accept either the full contract or a single-request convenience shape."
  (if (or (:role_permissions body) (:inline_policies body))
    body
    {:role_permissions [(select-keys body [:role :actions :resources])]
     :inline_policies  (if-some [p (:inline_attached body)]
                         [{:principal (str (:principal body "unknown")) :attached p}]
                         [])}))

(defn- decide [input]
  (let [resp       (http/post pdp-url
                               {:headers {"content-type" "application/json"}
                                :body    (json/generate-string {:input input})})
        parsed     (json/parse-string (:body resp) true)
        violations (get parsed :result [])]
    {:allowed    (empty? violations)
     :violations violations}))

(defn app [{:keys [request-method uri body] :as _req}]
  (try
    (cond
      (= uri "/healthz")
      {:status 200 :body (json/generate-string {:ok true})}

      (and (= request-method :post) (= uri "/v1/check"))
      (let [input (normalize (json/parse-string (slurp body) true))]
        {:status 200
         :headers {"Content-Type" "application/json"}
         :body (json/generate-string (decide input))})

      :else
      {:status 404 :body (json/generate-string {:error "not found" :hint "POST /v1/check"})})
    (catch Exception e
      {:status 500 :body (json/generate-string {:error (.getMessage e)})})))

(println "PEP listening on :8080 → PDP at" pdp-url)
(srv/run-server app {:port 8080})
