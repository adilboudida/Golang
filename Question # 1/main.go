package main

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/jackc/pgx/v4/stdlib"
)

var db *sql.DB

func main() {

	var err error
	db, err = sql.Open("pgx", "postgresql://username:password@localhost/user_management")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	r := gin.Default()

	r.POST("/api/users", createUser)
	r.POST("/api/users/generateotp", generateOTP)
	r.POST("/api/users/verifyotp", verifyOTP)

	if err := r.Run(":8080"); err != nil {
		panic(err)
	}
}

func createUser(c *gin.Context) {
	var user struct {
		Name        string `json:"name"`
		PhoneNumber string `json:"phone_number"`
	}
	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var existingUser struct {
		ID int
	}
	err := db.QueryRow("SELECT id FROM users WHERE phone_number = $1", user.PhoneNumber).Scan(&existingUser.ID)
	if err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Phone number already exists"})
		return
	} else if err != sql.ErrNoRows {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	var userID int
	err = db.QueryRow("INSERT INTO users (name, phone_number) VALUES ($1, $2) RETURNING id", user.Name, user.PhoneNumber).Scan(&userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User created successfully", "userID": userID})
}

func generateOTP(c *gin.Context) {
	var req struct {
		PhoneNumber string `json:"phone_number"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var userID int
	err := db.QueryRow("SELECT id FROM users WHERE phone_number = $1", req.PhoneNumber).Scan(&userID)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	otp := generateRandomOTP()

	_, err = db.Exec("UPDATE users SET otp = $1, otp_expiration_time = NOW() + INTERVAL '1 minute' WHERE id = $2", otp, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OTP"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "OTP generated successfully"})
}

func verifyOTP(c *gin.Context) {
	var req struct {
		PhoneNumber string `json:"phone_number"`
		OTP         string `json:"otp"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var userID int
	var storedOTP string
	var expirationTime time.Time
	err := db.QueryRow("SELECT id, otp, otp_expiration_time FROM users WHERE phone_number = $1", req.PhoneNumber).Scan(&userID, &storedOTP, &expirationTime)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	if req.OTP != storedOTP || time.Now().After(expirationTime) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid OTP or OTP expired"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "OTP verified successfully"})
}
