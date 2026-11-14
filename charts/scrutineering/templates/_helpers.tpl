{{- define "scrutineering.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "scrutineering.fullname" -}}
{{- if .Values.fullnameOverride }}{{ .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}{{ else }}{{ include "scrutineering.name" . }}{{ end }}
{{- end }}

{{- define "scrutineering.labels" -}}
app.kubernetes.io/name: {{ include "scrutineering.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "scrutineering.selector" -}}
app.kubernetes.io/name: {{ include "scrutineering.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "scrutineering.secretName" -}}
{{- if .Values.secrets.existingSecret }}{{ .Values.secrets.existingSecret }}{{ else }}{{ include "scrutineering.fullname" . }}-secrets{{ end }}
{{- end }}

{{- define "scrutineering.image" -}}
{{- $image := index .root.Values.images .component -}}
{{ printf "%s:%s" $image.repository $image.tag }}
{{- end }}
