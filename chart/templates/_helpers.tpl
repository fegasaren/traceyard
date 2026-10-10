{{- define "traceyard.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "traceyard.fullname" -}}
{{- default (printf "%s-%s" .Release.Name (include "traceyard.name" .)) .Values.fullnameOverride | trunc 54 | trimSuffix "-" -}}
{{- end -}}

{{- define "traceyard.selector" -}}
app.kubernetes.io/name: {{ include "traceyard.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: ui
{{- end -}}

{{- define "traceyard.postgresSelector" -}}
app.kubernetes.io/name: {{ include "traceyard.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: postgres
{{- end -}}

{{- define "traceyard.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}

{{- define "traceyard.validate" -}}
{{- $_ := required "existingSecret with database-url is required" .Values.existingSecret -}}
{{- $_ := required "publicOrigin is required (HTTP URL used by the browser)" .Values.publicOrigin -}}
{{- if not (regexMatch "^http://[^/]+$" .Values.publicOrigin) -}}
{{- fail "publicOrigin must be an HTTP origin without a path or trailing slash" -}}
{{- end -}}
{{- $_ := required "tempo.url is required" .Values.tempo.url -}}
{{- if .Values.postgres.enabled -}}
{{- if or (eq .Values.postgres.username "postgres") (hasPrefix "pg_" .Values.postgres.username) (not (regexMatch "^[a-z_][a-z0-9_-]{0,62}$" .Values.postgres.username)) -}}
{{- fail "postgres.username must be a non-bootstrap role (lowercase letters/digits/_/-, max 63 chars; not postgres or pg_*)" -}}
{{- end -}}
{{- end -}}
{{- if not (has .Values.service.type (list "ClusterIP" "NodePort")) -}}
{{- fail "service.type must be ClusterIP or NodePort" -}}
{{- end -}}
{{- if .Values.ingress.enabled -}}
{{- $_ := required "ingress.host is required when ingress is enabled" .Values.ingress.host -}}
{{- end -}}
{{- if empty .Values.networkPolicy.ldapCidrs -}}
{{- fail "networkPolicy.ldapCidrs must contain explicit AD/DC CIDRs before installation" -}}
{{- end -}}
{{- if empty .Values.networkPolicy.ldapPorts -}}
{{- fail "networkPolicy.ldapPorts must list the LDAP TCP ports used by ldapRealms" -}}
{{- end -}}
{{- range .Values.networkPolicy.ldapPorts -}}
{{- if or (not (regexMatch "^[0-9]+$" (toString .))) (lt (int .) 1) (gt (int .) 65535) -}}
{{- fail "networkPolicy.ldapPorts must contain TCP ports in [1, 65535]" -}}
{{- end -}}
{{- end -}}
{{- if and (eq .Values.service.type "NodePort") (empty .Values.networkPolicy.nodePortSourceCidrs) -}}
{{- fail "NodePort requires networkPolicy.nodePortSourceCidrs" -}}
{{- end -}}
{{- if .Values.networkPolicy.enabled -}}
{{- if and (not .Values.postgres.enabled) (empty .Values.networkPolicy.externalPostgresCidrs) -}}
{{- fail "External PostgreSQL requires networkPolicy.externalPostgresCidrs" -}}
{{- end -}}
{{- if or (empty .Values.tempo.podLabels) (empty .Values.networkPolicy.ingressController.podLabels) (empty .Values.networkPolicy.dns.podLabels) -}}
{{- fail "Tempo, ingress controller and DNS podLabels must be explicit nonempty selectors" -}}
{{- end -}}
{{- if and (or .Values.metrics.scrapeAnnotations .Values.metrics.serviceMonitor.enabled) (empty .Values.networkPolicy.prometheus.podLabels) -}}
{{- fail "Prometheus podLabels are required when metrics scraping is enabled" -}}
{{- end -}}
{{- end -}}
{{- range concat .Values.networkPolicy.ldapCidrs .Values.networkPolicy.nodePortSourceCidrs .Values.networkPolicy.externalPostgresCidrs .Values.trustedProxyCidrs -}}
{{- if or (not (contains "/" .)) (hasSuffix "/0" .) -}}
{{- fail "NetworkPolicy CIDRs must be explicit subnets; a hostname or /0 is not allowed" -}}
{{- end -}}
{{- end -}}
{{- end -}}
