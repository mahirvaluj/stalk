(defpackage :stalk
  (:use :cl)
  (:export :listen :connect :send :flush
           :stalk-connection :stalk-identity))

(in-package :stalk)


(defclass stalk-connection)
(defclass stalk-identity)

(defun listen (host port handler))
(defun connect (host port &optional identity &key handler))
(defun send (spack connection))
(defun flush (connection))
