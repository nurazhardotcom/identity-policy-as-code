(ns service.server-test
  (:require [cheshire.core :as json]
            [clojure.test :refer [deftest is testing]]
            [policy-service :as service])
  (:import (java.io ByteArrayInputStream)))

(defn- body-stream [text]
  (ByteArrayInputStream. (.getBytes text "UTF-8")))

(defn- response [status body]
  {:status status :body body})

(deftest normalize-keeps-the-full-contract-when-sections-are-null
  (testing "null is evidence of a missing section, not a reason to use convenience mode"
    (is (= {:role_permissions nil :inline_policies nil}
           (service/normalize {:role_permissions nil
                               :inline_policies nil})))
    (is (= {:role_permissions nil}
           (service/normalize {:role_permissions nil})))
    (is (= {:inline_policies nil}
           (service/normalize {:inline_policies nil})))))

(deftest malformed-or-empty-convenience-input-fails-closed
  (doseq [body [{}
                {:role "x"}
                {:role "x" :actions ["*"]}
                {:role "x" :resources []}
                {:role :x :actions ["*"] :resources []}
                {:principal "svc"}
                {:inline_attached "false"}
                {:inline_attached 1}]]
    (is (= {:role_permissions nil :inline_policies nil}
           (service/normalize body))
        (pr-str body))))

(deftest convenience-sections-may-be-supplied-independently
  (is (= {:role_permissions []
           :inline_policies [{:principal "svc" :attached true}]}
         (service/normalize {:principal "svc" :inline_attached true})))
  (is (= {:role_permissions [{:role "x"
                              :actions ["*"]
                              :resources []}]
           :inline_policies []}
         (service/normalize {:role "x"
                             :actions ["*"]
                             :resources []}))))

(deftest normalize-preserves-the-convenience-shape
  (is (= {:role_permissions [{:role "x"
                              :actions ["s3:GetObject"]
                              :resources ["arn:aws:s3:::bucket/*"]}]
          :inline_policies [{:principal "svc" :attached false}]}
         (service/normalize {:role "x"
                             :actions ["s3:GetObject"]
                             :resources ["arn:aws:s3:::bucket/*"]
                             :principal "svc"
                             :inline_attached false}))))

(deftest valid-empty-result-allows
  (is (= {:allowed true :violations []}
         (service/decide {}
                       (fn [_ _]
                         (response 200 "{\"result\":[]}"))))))

(deftest valid-deny-result-is-preserved
  (is (= {:allowed false
          :violations ["wildcard action granted to role 'x'"]}
         (service/decide {}
                       (fn [_ _]
                         (response 200
                                   "{\"result\":[\"wildcard action granted to role 'x'\"]}"))))))

(deftest missing-result-fails-closed
  (is (= {:allowed false
          :error "pdp-missing-result"
          :violations ["PDP response did not contain a result"]}
         (service/decide {}
                       (fn [_ _]
                         (response 200 "{}"))))))

(deftest malformed-pdp-response-fails-closed
  (doseq [[label body]
          [["nil-body" nil]
           ["not-json" "not-json"]
           ["not-an-object" "[]"]
           ["null-result" "{\"result\":null}"]
           ["object-result" "{\"result\":{}}"]
           ["non-string-result" "{\"result\":[1]}"]
           ["duplicate-result" "{\"result\":[\"x\",\"x\"]}"]]]
    (testing label
      (let [result (service/decide {} (fn [_ _] (response 200 body)))]
        (is (false? (:allowed result)))
        (is (= "pdp-malformed-response" (:error result)))))))

(deftest unsuccessful-pdp-response-fails-closed
  (doseq [fake-response [{:status 503 :body "service unavailable"}
                         {:body "{\"result\":[]}"}]]
    (let [result (service/decide {} (fn [_ _] fake-response))]
      (is (false? (:allowed result)))
      (is (= "pdp-http-error" (:error result))))))

(deftest pdp-exception-fails-closed
  (let [result (service/decide {} (fn [_ _] (throw (Exception. "connection refused"))))]
    (is (false? (:allowed result)))
    (is (= "pdp-request-error" (:error result)))))

(deftest app-sends-null-sections-through-to-the-decision
  (let [seen (atom nil)
        result (with-redefs [service/decide (fn [input]
                                              (reset! seen input)
                                              {:allowed false
                                               :violations ["denied"]})]
                 (service/app {:request-method :post
                               :uri "/v1/check"
                               :body (body-stream
                                      "{\"role_permissions\":null,\"inline_policies\":null}")}))]
    (is (= {:role_permissions nil :inline_policies nil} @seen))
    (is (= 200 (:status result)))
    (is (false? (get (json/parse-string (:body result) true) :allowed)))))

(deftest app-rejects-non-object-request-with-explicit-null-sections
  (let [seen (atom nil)
        result (with-redefs [service/decide (fn [input]
                                              (reset! seen input)
                                              {:allowed false
                                               :violations ["denied"]})]
                 (service/app {:request-method :post
                               :uri "/v1/check"
                               :body (body-stream "null")}))]
    (is (= {:role_permissions nil :inline_policies nil} @seen))
    (is (false? (get (json/parse-string (:body result) true) :allowed)))))

(deftest app-rejects-an-empty-object-as-a-malformed-request
  (let [seen (atom nil)
        result (with-redefs [service/decide (fn [input]
                                              (reset! seen input)
                                              {:allowed false
                                               :violations ["denied"]})]
                 (service/app {:request-method :post
                               :uri "/v1/check"
                               :body (body-stream "{}")}))]
    (is (= {:role_permissions nil :inline_policies nil} @seen))
    (is (false? (get (json/parse-string (:body result) true) :allowed)))))

(deftest app-rejects-malformed-request-with-an-explicit-deny
  (let [result (service/app {:request-method :post
                             :uri "/v1/check"
                             :body (body-stream "not-json")})
        parsed (json/parse-string (:body result) true)]
    (is (= 500 (:status result)))
    (is (false? (:allowed parsed)))
    (is (= "request-error" (:error parsed)))))
