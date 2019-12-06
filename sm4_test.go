/***************************************************************************
 *
 * Copyright (c) 2019 github.com, Inc. All Rights Reserved
 * sm4 encrypt test
 * Author scloudrun
 *
**************************************************************************/

package sm4lib

import (
	"reflect"
	"testing"
)

var (
	defaultKey     = []byte("0000000000000000")
	defaultIv      = []byte("1111111111111111")
	defaultEncData = []byte("scloudrun")
	defaultEncByte = []byte{54, 214, 183, 79, 105, 233, 133, 146, 228, 57, 231, 154, 21, 241, 170, 7}
)

func Test_Sm4Enc(t *testing.T) {
	type args struct {
		key           []byte
		iv            []byte
		plantText     []byte
		paddingStatus bool
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			"Test_Sm4Enc",
			args{defaultKey, defaultIv, defaultEncData, true},
			defaultEncByte,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Sm4Enc(tt.args.key, tt.args.iv, tt.args.plantText, tt.args.paddingStatus)
			if (err != nil) != tt.wantErr {
				t.Errorf("Sm4Enc() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Sm4Enc() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_Sm4Dec(t *testing.T) {
	type args struct {
		key           []byte
		iv            []byte
		ciphertext    []byte
		paddingStatus bool
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			"Test_sm4dec",
			args{defaultKey, defaultIv, defaultEncByte, true},
			[]byte(defaultEncData),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Sm4Dec(tt.args.key, tt.args.iv, tt.args.ciphertext, tt.args.paddingStatus)
			if (err != nil) != tt.wantErr {
				t.Errorf("Sm4Dec() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Sm4Dec() = %v, want %v", got, tt.want)
			}
		})
	}
}
