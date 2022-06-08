package service

import (
	"fmt"

	"github.com/aveplen-bach/authentication-service/internal/model"
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
	var users []model.User
	result := us.db.Find(&users)

	if result.Error != nil {
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
	user := &model.User{}

	result := us.db.Where("username = ?", username).First(user)
	if result.Error != nil {
		return nil, fmt.Errorf("could not fetch user from db: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return nil, fmt.Errorf("user with given username not found in db")
	}

	return user, nil
}

func (us *UserService) NewUser(user *model.User) error {
	result := us.db.Save(user)

	if result.Error != nil {
		return fmt.Errorf("could not save user to db: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("user did not save?")
	}

	return nil
}
