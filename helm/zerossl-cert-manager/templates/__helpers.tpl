{{/*
Expand the namespace of the release.
Allows overriding.
*/}}
{{- define "zerossl_cert_manager.namespace" -}}
{{- default .Release.Namespace .Values.namespace -}}
{{- end -}}

{{/*
Expand the name of the chart.
*/}}
{{- define "zerossl_cert_manager.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "zerossl_cert_manager.fullname" -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- default (printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-") .Values.fullnameOverride -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "zerossl_cert_manager.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Set paths for images
*/}}
{{- define "zerossl_cert_manager.image" -}}
{{- if .Values.image.tag -}}
{{ .Values.image.repository }}:{{ .Values.image.tag }}
{{- else -}}
{{ .Values.image.repository }}:{{ .Chart.AppVersion }}
{{- end -}}
{{- end -}}

{{/*
Selector labels
*/}}
{{- define "zerossl_cert_manager.selectorLabels" -}}
app.kubernetes.io/name: {{ include "zerossl_cert_manager.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Create metalabels
*/}}
{{- define "zerossl_cert_manager.metaLabels" -}}
{{ include "zerossl_cert_manager.selectorLabels" . }}
helm.sh/chart: {{ template "zerossl_cert_manager.chart" . }}
app.kubernetes.io/managed-by: "{{ .Release.Service }}"
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- if .Values.metaLabels}}
{{ toYaml .Values.metaLabels }}
{{- end }}
{{- end -}}
{{/*
Daemonset would be deployed by cronjob
*/}}
{{- define "zerossl_cert_manager.daemonset" -}}
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: zerossl-cert-manager-{{ (include "zerossl_cert_manager.fullname" .) }}
  namespace: {{ include "zerossl_cert_manager.namespace" . }}
  labels:
    {{- include "zerossl_cert_manager.metaLabels" . | nindent 4 }}
    app.kubernetes.io/component: zerossl-cert-manager
spec:
  selector:
    matchLabels:
      app.kubernetes.io/component: zerossl-cert-manager
      {{- include "zerossl_cert_manager.selectorLabels" . | nindent 6 }}
  template:
    metadata:
      labels:
        {{- include "zerossl_cert_manager.metaLabels" . | nindent 8 }}
        app.kubernetes.io/component: zerossl-cert-manager
    spec:
      serviceAccountName: default
      {{- if .Values.priorityClass.enabled }}
      priorityClassName: {{ .Values.priorityClass.name }}
      {{- end }}
      {{- if .Values.nodeSelector }}
      nodeSelector:
        {{- range $key, $value := .Values.nodeSelector }}
        {{ $key }}: {{ $value | quote }}
        {{- end }}
      {{- end }}
      {{ if .Values.tolerations }}
      tolerations:
      {{- range .Values.tolerations }}
        - key: {{ .key | quote }}
          operator: {{ .operator | default "Equal" | quote }}
          value: {{ .value | quote }}
          effect: {{ .effect | quote }}
      {{- end }}
      {{- end }}
      initContainers:
        - name: zerossl-cert-manager
          image: {{ include "zerossl_cert_manager.image" . }}
        {{- if eq .Values.networkMode "hostPort" }}
          ports:
            - containerPort: 80
              hostPort: 80
        {{ end }}
          env:
          - name: ZEROSSL_API_KEY
            value: {{ .Values.env.ZEROSSL_API_KEY }}
          - name: NODE_NAME
            valueFrom:
              fieldRef:
                fieldPath: spec.nodeName
          - name: KUBE_INFO_SERVICE
            value: "kubeinfo-service"
          - name: LOG_LEVEL
            value: {{ .Values.env.LOG_LEVEL }}
          - name: RENEWAL_THRESHOLD_DAYS
            value: "{{ .Values.env.RENEWAL_THRESHOLD_DAYS }}"
          resources:
            requests:
              memory: "64Mi"
              cpu: "50m"
            limits:
              memory: "128Mi"
              cpu: "100m"
          volumeMounts:
            - name: host-volume
              mountPath: /certs
          securityContext:
            capabilities:
              add: ["NET_BIND_SERVICE"]
            runAsUser: 0
      containers:
       - name: pause-container
{{- if eq .Values.type "cronjob" }}
         image: k8s.gcr.io/pause:3.5
{{- else }}
{{- if eq .Values.type "daemonset" }}
         image: busybox:1.37.0
         command: ["sh", "-c", "echo \"now $(date), sleep {{ .Values.daemonset.activeDeadlineSeconds }} seconds\"; sleep {{ .Values.daemonset.activeDeadlineSeconds }}"] 
{{- else }}
  {{ fail "Invalid value for type. Use cronjob or daemonset." }}
{{- end -}}
{{- end }}
{{ if eq .Values.networkMode "hostNetwork" }}
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
{{ end }}


      volumes:
        - name: host-volume
          hostPath:
            path: /certs
            type: DirectoryOrCreate
{{- end -}}
