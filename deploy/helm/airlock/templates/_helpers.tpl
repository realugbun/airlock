{{- define "airlock.fullname" -}}
{{- .Release.Name }}
{{- end -}}

{{- define "airlock.labels" -}}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
