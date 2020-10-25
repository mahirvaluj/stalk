(defpackage :stalk
  (:use :cl)
  (:shadow :identity)
  (:export :listener :host :port :peer-identity :socket :identity
           :connect :send :flush :identity :recv :wait-for-input
           :socket :cipher))
