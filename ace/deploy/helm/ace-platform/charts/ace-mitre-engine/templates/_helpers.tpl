{{- define "ace-mitre-engine.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- define "ace-mitre-engine.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name (include "ace-mitre-engine.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- define "ace-mitre-engine.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{ include "ace-mitre-engine.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}
{{- define "ace-mitre-engine.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ace-mitre-engine.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
{{- define "ace-mitre-engine.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "ace-mitre-engine.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}
