package client

type Repository interface {
	Save(Client)
	GetByID(string) Client
}

type clientRepository struct {
	inMemory []Client
}

func NewRepository() Repository {
	return &clientRepository{
		inMemory: []Client{},
	}
}

func (r *clientRepository) Save(c Client) {
	r.inMemory = append(r.inMemory, c)
}

func (r *clientRepository) GetByID(ID string) Client {
	for _, c := range r.inMemory {
		if c.ID == ID {
			return c
		}
	}
	return Client{}
}
