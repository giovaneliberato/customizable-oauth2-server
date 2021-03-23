package infra

import (
	"path"
	"path/filepath"
	"runtime"

	"github.com/spf13/viper"
)

func rootDir() string {
	_, b, _, _ := runtime.Caller(0)
	d := path.Join(path.Dir(b))
	return filepath.Dir(d)
}

func LoadConfig() {
	viper.AddConfigPath(rootDir())
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")

	err := viper.ReadInConfig()
	if err != nil {
		panic(err)
	}
}
