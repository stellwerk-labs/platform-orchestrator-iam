package config

import (
	"testing"
)

const connectionString = "amqp://user:pass@host:5672/vhost" //nolint:gosec

func TestConfiguration_GetAmqpConnectionString(t *testing.T) {
	tests := []struct {
		name    string
		config  Configuration
		want    string
		wantErr bool
	}{
		{
			name: "AmqpConnectionString is set",
			config: Configuration{
				AmqpConnectionString: connectionString,
			},
			want:    connectionString,
			wantErr: false,
		},
		{
			name: "Individual fields are set",
			config: Configuration{
				AmpqHost:     "host",
				AmpqPort:     "5672",
				AmpqVhost:    "vhost",
				AmpqUsername: "user",
				AmpqPassword: "pass",
			},
			want:    connectionString,
			wantErr: false,
		},
		{
			name: "Missing Host",
			config: Configuration{
				AmpqPort:     "5672",
				AmpqVhost:    "vhost",
				AmpqUsername: "user",
				AmpqPassword: "pass",
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Missing Vhost",
			config: Configuration{
				AmpqHost:     "host",
				AmpqPort:     "5672",
				AmpqUsername: "user",
				AmpqPassword: "pass",
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Missing Username",
			config: Configuration{
				AmpqHost:     "host",
				AmpqPort:     "5672",
				AmpqVhost:    "vhost",
				AmpqPassword: "pass",
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Missing Password",
			config: Configuration{
				AmpqHost:     "host",
				AmpqPort:     "5672",
				AmpqVhost:    "vhost",
				AmpqUsername: "user",
			},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.config.GetAmqpConnectionString()
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAmqpConnectionString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetAmqpConnectionString() got = %v, want %v", got, tt.want)
			}
		})
	}
}
