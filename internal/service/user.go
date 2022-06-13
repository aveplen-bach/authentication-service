package service

import (
	"fmt"

	"github.com/aveplen-bach/authentication-service/internal/model"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type UserService struct {
	db *gorm.DB
}

func NewUserService(db *gorm.DB) *UserService {
	return &UserService{
		db: db,
	}
}

func (us *UserService) GetAllUsers() ([]model.UserDto, error) {
	logrus.Info("getting all users")
	var users []model.User
	result := us.db.Find(&users)

	if result.Error != nil {
		logrus.Errorf("could not fetch users from db: %w", result.Error)
		return nil, fmt.Errorf("could not fetch users from db: %w", result.Error)
	}

	var userDtos []model.UserDto
	for _, user := range users {
		userDtos = append(userDtos, model.UserDto{
			UserID:    user.ID,
			Username:  user.Username,
			Admin:     user.Admin,
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
		})
	}

	return userDtos, nil
}

func (us *UserService) GetUserByUsername(username string) (*model.User, error) {
	logrus.Info("getting user by username")
	user := &model.User{}

	result := us.db.Where("username = ?", username).First(user)
	if result.Error != nil {
		logrus.Error("could not fetch user from db: %w", result.Error)
		return nil, fmt.Errorf("could not fetch user from db: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		logrus.Error("user with given username not found in db")
		return nil, fmt.Errorf("user with given username not found in db")
	}

	return user, nil
}

func (us *UserService) NewUser(user *model.User) error {
	logrus.Info("saving new user")
	result := us.db.Save(user)

	if result.Error != nil {
		logrus.Errorf("could not save user to db: %w", result.Error)
		return fmt.Errorf("could not save user to db: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		logrus.Errorf("user did not save?")
		return fmt.Errorf("user did not save?")
	}

	return nil
}
