(ns policy-service
  "Request-time PEP for the iam.guard policy.

  The OPA Data API is the PDP.  A response is trusted only when it is a
  successful JSON object with a string-array result.  Every other outcome,
  including an absent result, is an explicit deny."
  (:require [babashka.http-client :as http]
            [cheshire.core :as json]
            [org.httpkit.server :as srv]))

(def pdp-url
  "The PDP endpoint for data.iam.guard.deny."
  "http://127.0.0.1:8181/v1/data/iam/guard/deny")

(def ^:private convenience-role-keys [:role :actions :resources])
(def ^:private convenience-inline-keys [:principal :inline_attached])
(def ^:private convenience-keys
  (into #{} (concat convenience-role-keys convenience-inline-keys)))

(defn- string-vector? [value]
  (and (vector? value) (every? string? value)))

(defn- normalize-convenience [body]
  (let [role-fields?    (some #(contains? body %) convenience-role-keys)
        inline-fields?  (some #(contains? body %) convenience-inline-keys)
        role-valid?     (or (not role-fields?)
                            (and (string? (:role body))
                                 (string-vector? (:actions body))
                                 (string-vector? (:resources body))))
        inline-valid?   (and (or (not inline-fields?)
                                 (boolean? (:inline_attached body)))
                             (or (not (contains? body :principal))
                                 (string? (:principal body))))]
    (if-not (or role-fields? inline-fields?)
      ;; No recognized evidence at all is malformed, not a clean role.
      {:role_permissions nil :inline_policies nil}
      (if-not (and role-valid? inline-valid?)
        ;; Preserve fail-closed policy semantics for malformed convenience
        ;; fields rather than manufacturing empty or nil role permissions.
        {:role_permissions nil :inline_policies nil}
        {:role_permissions (if role-fields?
                             [{:role (:role body)
                               :actions (:actions body)
                               :resources (:resources body)}]
                             [])
         :inline_policies (if inline-fields?
                            [{:principal (:principal body "unknown")
                              :attached (:inline_attached body)}]
                            [])}))))

(defn normalize
  "Normalize the full input contract or the single-request convenience shape.

  A section key being present is significant even when its value is nil.  The
  old truthiness check treated an all-null contract as the convenience shape,
  which could turn absent evidence into an apparently valid request.  An empty
  or incomplete convenience object is likewise converted to explicit null
  sections so the production policy denies it."
  [body]
  (cond
    (not (map? body))
    {:role_permissions nil :inline_policies nil}

    (or (contains? body :role_permissions)
        (contains? body :inline_policies))
    body

    (some #(contains? body %) convenience-keys)
    (normalize-convenience body)

    :else
    {:role_permissions nil :inline_policies nil}))

(defn- error-decision [code message]
  {:allowed    false
   :error      code
   :violations [message]})

(defn- successful-response? [response]
  (and (map? response)
       (integer? (:status response))
       (<= 200 (:status response) 299)))

(defn- decision-from-pdp-body [body]
  (let [parsed (if (string? body)
                 (try
                   (json/parse-string body true)
                   (catch Exception _ ::malformed))
                 ::malformed)
        result  (when (map? parsed) (:result parsed))]
    (cond
      (not (string? body))
      (error-decision "pdp-malformed-response"
                      "PDP response body was not JSON text")

      (not (map? parsed))
      (error-decision "pdp-malformed-response"
                      "PDP response was not a JSON object")

      (not (contains? parsed :result))
      (error-decision "pdp-missing-result"
                      "PDP response did not contain a result")

      (not (vector? result))
      (error-decision "pdp-malformed-response"
                      "PDP result was not an array")

      (not (and (every? string? result)
                (= (count result) (count (set result)))))
      (error-decision "pdp-malformed-response"
                      "PDP result was not an array of unique strings")

      :else
      {:allowed    (empty? result)
       :violations (vec result)})))

(defn decide
  "Return a deny-by-default decision from a PDP response.

  The optional post-fn makes the response contract directly testable without
  a running OPA server.  The production arity uses the HTTP client."
  ([input]
   (decide input nil))
  ([input post-fn]
   (let [post-fn (or post-fn
                     (fn [url request]
                       (http/post url request)))]
     (try
       (let [request {:headers {"content-type" "application/json"}
                      :body    (json/generate-string {:input input})
                      ;; Inspect non-2xx responses ourselves so they become a
                      ;; stable PDP error decision rather than an HTTP-client
                      ;; exception with a different failure path.
                      :throw   false}
             response (post-fn pdp-url request)]
         (if-not (successful-response? response)
           (error-decision "pdp-http-error"
                           "PDP returned an unsuccessful HTTP response")
           (decision-from-pdp-body (:body response))))
       (catch Exception _
         ;; Includes connection failures, exceptions from the HTTP client, and
         ;; errors while serializing the request.  None can become an allow.
         (error-decision "pdp-request-error"
                         "PDP request failed"))))))

(defn- request-error-response [code message]
  {:status  500
   :headers {"Content-Type" "application/json"}
   :body    (json/generate-string (error-decision code message))})

(defn app [{:keys [request-method uri body] :as _request}]
  (try
    (cond
      (= uri "/healthz")
      {:status 200 :body (json/generate-string {:ok true})}

      (and (= request-method :post) (= uri "/v1/check"))
      (let [input   (normalize (json/parse-string (slurp body) true))
            decision (decide input)]
        {:status  200
         :headers {"Content-Type" "application/json"}
         :body    (json/generate-string decision)})

      :else
      {:status  404
       :headers {"Content-Type" "application/json"}
       :body    (json/generate-string {:error "not found"
                                       :hint  "POST /v1/check"})})
    (catch Exception _
      (request-error-response "request-error" "request failed"))))

(defn -main [& _args]
  (println "PEP listening on :8080 → PDP at" pdp-url)
  (srv/run-server app {:port 8080}))
