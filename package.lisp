(defpackage :stalk
  (:use :cl)
  (:shadow :identity)
  (:export :listener :connect :send :flush
           :stalk-outgoing :stalk-identity
           :register-spack-handler))
