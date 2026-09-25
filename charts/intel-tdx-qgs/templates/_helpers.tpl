{{- define "intel-tdx-qgs.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "intel-tdx-qgs.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "intel-tdx-qgs.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "intel-tdx-qgs.labels" -}}
app.kubernetes.io/name: {{ include "intel-tdx-qgs.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
app.kubernetes.io/part-of: intel-tdx-qgs
app.kubernetes.io/mode: {{ .Values.tdxQuoteGenerationService.mode | lower | quote }}
{{- end -}}

{{- define "intel-tdx-qgs.selectorLabels" -}}
app.kubernetes.io/name: {{ include "intel-tdx-qgs.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "intel-tdx-qgs.qgsName" -}}
{{- printf "%s-qgs" .Values.tdxQuoteGenerationService.name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "intel-tdx-qgs.registrarName" -}}
{{- printf "%s-registrar" .Values.tdxQuoteGenerationService.name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "intel-tdx-qgs.pcsSecretName" -}}
{{- if .Values.pcsApiKey.existingSecret -}}
{{- .Values.pcsApiKey.existingSecret -}}
{{- else -}}
{{- .Values.pcsApiKey.secretName -}}
{{- end -}}
{{- end -}}

