NAME = netscan

CXX = c++
CXXFLAGS = -Wall -Wextra -Werror -std=c++17 -MMD -MP -I include

SRC = models/main.cpp models/scanner.cpp
OBJ = $(SRC:.cpp=.o)
DEP = $(SRC:.cpp=.d)

all: $(NAME)

$(NAME): $(OBJ)
	@$(CXX) $(CXXFLAGS) $(OBJ) -o $(NAME)

-include $(DEP)

%.o: %.cpp
	@$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	@rm -rf $(OBJ)
	@rm -rf $(DEP)

fclean: clean
	@rm -rf $(NAME)

re: fclean all

.PHONY: all clean fclean re