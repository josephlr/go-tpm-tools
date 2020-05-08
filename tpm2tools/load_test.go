package tpm2tools

import (
	"testing"

	"github.com/google/go-tpm/tpm2"

	"github.com/google/go-tpm-tools/internal"
)

var hmacKeyTemplate = tpm2.Public{
	Type:       tpm2.AlgKeyedHash,
	NameAlg:    tpm2.AlgSHA256,
	Attributes: tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth | tpm2.FlagSign,
	KeyedHashParameters: &tpm2.KeyedHashParams{
		Alg:  tpm2.AlgHMAC,
		Hash: tpm2.AlgSHA256,
	},
}

func BenchmarkLoad(b *testing.B) {
	b.StopTimer()

	rwc := internal.GetTPM(b)
	defer CheckedClose(b, rwc)

	srk, err := StorageRootKeyECC(rwc)
	if err != nil {
		b.Fatal(err)
	}
	defer srk.Close()

	priv, pub, _, _, _, err := tpm2.CreateKey(rwc, srk.Handle(), tpm2.PCRSelection{}, "", "", hmacKeyTemplate)
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		key, _, err := tpm2.Load(rwc, srk.Handle(), "", pub, priv)
		if err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		tpm2.FlushContext(rwc, key)
	}
}

func BenchmarkContext(b *testing.B) {
	b.StopTimer()

	rwc := internal.GetTPM(b)
	defer CheckedClose(b, rwc)

	srk, err := StorageRootKeyECC(rwc)
	if err != nil {
		b.Fatal(err)
	}
	defer srk.Close()

	priv, pub, _, _, _, err := tpm2.CreateKey(rwc, srk.Handle(), tpm2.PCRSelection{}, "", "", hmacKeyTemplate)
	if err != nil {
		b.Fatal(err)
	}
	key, _, err := tpm2.Load(rwc, srk.Handle(), "", pub, priv)
	if err != nil {
		b.Fatal(err)
	}
	context, err := tpm2.ContextSave(rwc, key)
	if err != nil {
		b.Fatal(err)
	}
	tpm2.FlushContext(rwc, key)

	for i := 0; i < b.N; i++ {
		b.StartTimer()
		loaded, err := tpm2.ContextLoad(rwc, context)
		if err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		tpm2.FlushContext(rwc, loaded)
	}
}
