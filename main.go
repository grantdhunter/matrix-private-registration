package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/go-redis/redis/v7"
	"html/template"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type Configuration struct {
	MatrixServer       string `json:"matrixServer"`
	MatrixSharedSecret string `json:"matrixSharedSecret"`
	Address            string `json:"address"`

	RegistrationServer  string `json:"registrationServer"`
	RegistrationTimeout int64  `json:"registrationTimeout"`
	RegistrationSecret  string `json:"registrationSecret"`
	RedisServer         string `json:"redisServer"`
	RedisPassword       string `json:"redisPassword"`
	RedisDb             int    `json:"redisDb"`
}

type UserRequest struct {
	Nonce     string  `json:"nonce"`
	Username  string  `json:"username"`
	Password  string  `json:"password"`
	Mac       string  `json:"mac"`
	Admin     bool    `json:"admin"`
	User_type *string `json:"user_type"`
}

func loadConfig() Configuration {
	file, _ := os.Open("./config.json")
	defer file.Close()

	bytes, _ := ioutil.ReadAll(file)

	var config Configuration
	err := json.Unmarshal(bytes, &config)

	if err != nil {
		log.Fatal("Config error: ", err)
	}

	return config
}

func parse_response(resp *http.Response) map[string]string {
	var body map[string]string
	body_str, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		log.Fatal(err)
		return body
	}

	json.Unmarshal(body_str, &body)
	return body
}

type App struct {
	Config Configuration
	Redis  *redis.Client
}

func (app *App) registrationHandler(w http.ResponseWriter, r *http.Request) {
	template_context := map[string]string{"matrixServer": app.Config.MatrixServer}
	if r.Method == "GET" {
		t, _ := template.ParseFiles("templates/register.html")
		t.Execute(w, template_context)
	} else if r.Method == "POST" {
		r.ParseForm()
		result := app.registerUser(r.Form["username"][0], r.Form["password"][0])
		t, _ := template.ParseFiles("templates/register_result.html")
		template_context["result"] = result
		t.Execute(w, template_context)
	}

}

func (app *App) registerUser(user string, password string) string {
	url := fmt.Sprintf("https://%s/_matrix/client/r0/admin/register", app.Config.MatrixServer)

	resp, _ := http.Get(url)
	body := parse_response(resp)

	mac := hmac.New(sha1.New, []byte(app.Config.MatrixSharedSecret))
	mac.Write([]byte(body["nonce"]))
	mac.Write([]byte("\x00"))
	mac.Write([]byte(user))
	mac.Write([]byte("\x00"))
	mac.Write([]byte(password))
	mac.Write([]byte("\x00"))
	mac.Write([]byte("notadmin"))

	macString := hex.EncodeToString(mac.Sum(nil))
	data := UserRequest{
		Nonce:     body["nonce"],
		Username:  user,
		Password:  password,
		Mac:       macString,
		Admin:     false,
		User_type: nil,
	}

	buf, _ := json.Marshal(&data)

	if true {
		resp, _ = http.Post(url, "application/json", bytes.NewBuffer(buf))
		body := parse_response(resp)

		if resp.StatusCode == http.StatusOK {
			return "All signed up!"
		} else {
			return fmt.Sprintf("Something when wrong: %d, %s", resp.StatusCode, body["error"])
		}
	}

	return "Test complete"
}

func (app *App) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth_string := r.URL.Query().Get("a")
		log.Println(auth_string)
		if len(auth_string) <= 0 {
			w.WriteHeader(http.StatusUnauthorized)
			return

		}

		auth_parts := strings.Split(auth_string, ".")

		if len(auth_parts) != 2 {
			log.Println(auth_parts)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		key := auth_parts[0]
		client_hash := auth_parts[1]

		server_string, err := app.Redis.Get(key).Result()

		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		h := sha256.New()
		h.Write([]byte(fmt.Sprintf("%s.%s.%s", key, app.Config.RegistrationSecret, server_string)))
		server_hash := hex.EncodeToString(h.Sum(nil))

		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if client_hash != server_hash {
			log.Println("Tokens don't match.")
			log.Printf("%s != %s\n", client_hash, server_hash)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		server_token := strings.Split(server_string, ".")
		date, err := strconv.ParseInt(server_token[1], 10, 64)

		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		now := time.Now().Unix()

		if date-now < 0 {
			log.Println("Token expired.")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func genString(length int64) string {
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	chars := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"abcdefghijklmnopqrstuvwxyz" +
		"0123456789")

	var b strings.Builder

	for i := int64(0); i < length; i++ {
		b.WriteRune(chars[seededRand.Intn(len(chars))])
	}

	return b.String()
}

func (app *App) invite() {

	key := genString(5)
	salt := genString(25)
	timeout := app.Config.RegistrationTimeout
	timestamp := time.Now().Unix() + timeout

	token := fmt.Sprintf("%s.%d", salt, timestamp)

	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%s.%s.%s", key, app.Config.RegistrationSecret, token)))
	server_hash := hex.EncodeToString(h.Sum(nil))

	err := app.Redis.Set(key, token, 0).Err()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("https://%s/register?a=%s.%s\n", app.Config.RegistrationServer, key, server_hash)

}

func main() {
	var server = flag.Bool("server", false, "run server")
	var invite = flag.Bool("invite", false, "create invite link")
	flag.Parse()

	config := loadConfig()
	app := &App{
		Config: config,
		Redis: redis.NewClient(&redis.Options{
			Addr:     config.RedisServer,
			Password: config.RedisPassword,
			DB:       config.RedisDb,
		}),
	}

	if *server {
		fmt.Println("Starting Server...")
		http.Handle("/", app.AuthMiddleware(http.HandlerFunc(app.registrationHandler)))

		err := http.ListenAndServe(app.Config.Address, nil)

		if err != nil {
			log.Fatal("ListenAndServe: ", err)
		}
	}

	if *invite {
		fmt.Println("Invite URL:")
		app.invite()
	}

}
