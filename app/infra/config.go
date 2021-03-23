package infra

import "github.com/spf13/viper"

func LoadConfig() {
	viper.SetConfigName("config") // name of config file (without extension)
	viper.SetConfigType("yaml")
	viper.AddConfigPath("../")
	err := viper.ReadInConfig()
	if err != nil {
		panic(err)
	}
}

func InitializeApp() {
	LoadConfig()
	InitializeComponents()
}
