package parity

import "testing"

func TestDecreaseReason(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "absent",
			body: "just a plain description of the change",
			want: "",
		},
		{
			name: "present on its own",
			body: "Parity-decrease: moved behind P4",
			want: "moved behind P4",
		},
		{
			name: "indented",
			body: "   Parity-decrease: moved behind P4",
			want: "moved behind P4",
		},
		{
			name: "mid body on its own line",
			body: "This PR does a thing.\n\nParity-decrease: moved behind P4\n\nMore detail follows.",
			want: "moved behind P4",
		},
		{
			name: "mixed case marker",
			body: "PARITY-DECREASE: moved behind P4",
			want: "moved behind P4",
		},
		{
			name: "trailing whitespace is trimmed",
			body: "Parity-decrease: moved behind P4   ",
			want: "moved behind P4",
		},
		{
			name: "crlf line ending is trimmed",
			body: "Parity-decrease: moved behind P4\r\n",
			want: "moved behind P4",
		},
		{
			name: "mid-line prose mention does not match",
			body: "some text Parity-decrease: moved behind P4",
			want: "",
		},
		{
			name: "prose sentence containing the marker does not match",
			body: "This does not need a Parity-decrease: label",
			want: "",
		},
		{
			name: "markdown bullet does not match",
			body: "- Parity-decrease: moved behind P4",
			want: "",
		},
		{
			name: "only the first of several lines is used",
			body: "Parity-decrease: first reason\nParity-decrease: second reason",
			want: "first reason",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DecreaseReason(tt.body); got != tt.want {
				t.Errorf("DecreaseReason(%q) = %q, want %q", tt.body, got, tt.want)
			}
		})
	}
}
