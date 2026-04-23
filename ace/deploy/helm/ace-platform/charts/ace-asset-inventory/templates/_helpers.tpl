{{- define "ace-asset-inventory.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- define "ace-asset-inventory.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name (include "ace-asset-inventory.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- define "ace-asset-inventory.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{ include "ace-asset-inventory.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}
{{- define "ace-asset-inventory.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ace-asset-inventory.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
{{- define "ace-asset-inventory.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "ace-asset-inventory.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}
