package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	ID            uint `gorm:"primaryKey"`
	Username      string
	Password_hash []byte
}
type File struct {
	ID        uint `gorm:"primaryKey"`
	UserID    uint
	Filename  string
	File_path string
}

type Login struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func InitDB() (db *gorm.DB) {

	db, err := gorm.Open(sqlite.Open("db.sqlite3"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	db.AutoMigrate(&User{}, &File{})

	// // Create user
	// password := "123456"
	// hashed_pass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }

	// user := User{
	// 	Username:      "test",
	// 	Password_hash: hashed_pass,
	// }
	// db.Create(&user)

	return db

}

func generateJWT(id int) string {
	var secretKey = []byte("80C9C76E9A7404715831ACD8DA1C15F27954CBAE09A7D11E0976AC21112E6030")

	claims := jwt.MapClaims{
		"exp": time.Now().Add(12 * time.Hour).Unix(),
		"id":  id,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		fmt.Println(err)
	}

	return tokenString
}

func middlewareCheck(c *gin.Context) {
	authorizationHeader := c.GetHeader("Authorization")
	if authorizationHeader == "" {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	bearerToken := strings.Split(authorizationHeader, " ")

	token, err := jwt.Parse(bearerToken[1], func(token *jwt.Token) (interface{}, error) {

		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte("80C9C76E9A7404715831ACD8DA1C15F27954CBAE09A7D11E0976AC21112E6030"), nil
	})

	if err != nil {
		fmt.Println(err)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		c.Request.Header.Add("userId", fmt.Sprint(claims["id"]))
	} else {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

}

func main() {
	r := gin.Default()

	db := InitDB()

	r.POST("/login", func(c *gin.Context) {

		var login Login
		c.ShouldBindJSON(&login)

		username := login.Username
		password := login.Password

		var user User
		db.Where("username = ?", username).First(&user)

		err := bcrypt.CompareHashAndPassword(user.Password_hash, []byte(password))
		if err == nil {
			c.JSON(http.StatusOK, gin.H{
				"token": generateJWT(int(user.ID)),
			})

		} else {
			fmt.Println("Password is incorrect")
		}

	})

	r.POST("/upload-picture", middlewareCheck, func(c *gin.Context) {

		file, header, err := c.Request.FormFile("picture")
		if err != nil {
			fmt.Println(err)
			return
		}
		defer file.Close()

		filename := header.Filename

		userID, _ := strconv.Atoi(c.Request.Header.Get("userId"))

		if _, err := os.Stat("images/" + strconv.Itoa(userID)); os.IsNotExist(err) {
			log.Println("Directory does not exist, creating it...")
			os.MkdirAll("images/"+strconv.Itoa(userID)+"/", os.ModePerm)
		}

		out, err := os.Create("images/" + strconv.Itoa(userID) + "/" + filename)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer out.Close()

		file_ := File{
			UserID:    uint(userID),
			Filename:  filename,
			File_path: "images/" + strconv.Itoa(userID) + "/" + filename,
		}
		db.Create(&file_)

		_, err = io.Copy(out, file)
		if err != nil {
			fmt.Println(err)
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status": "Image uploaded successfully",
		})

	})

	r.POST("/images", middlewareCheck, func(c *gin.Context) {

		userID, _ := strconv.Atoi(c.Request.Header.Get("userId"))

		var files []File
		db.Where("user_id = ?", userID).Find(&files)

		fmt.Println(files)
		c.JSON(http.StatusOK, gin.H{"debug": files})

	})
	r.Run(":8102")
}
