{{- define "ace-threat-intel.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- define "ace-threat-intel.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name (include "ace-threat-intel.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- define "ace-threat-intel.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{ include "ace-threat-intel.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}
{{- define "ace-threat-intel.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ace-threat-intel.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
{{- define "ace-threat-intel.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "ace-threat-intel.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}
