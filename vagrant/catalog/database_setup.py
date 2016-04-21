from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
 
Base = declarative_base()


class User(Base):
  __tablename__ = 'user'

  id = Column(Integer, primary_key = True)
  name = Column(String(250), nullable = False)
  email = Column(String(250), nullable = False  )
  picture = Column(String(250))

  @property 
  def serialize(self):
    """ Return object data in easily serializeable format"""
    return {
      'id' : self.id,
      'name' : self.name  ,
      'email' : self.email,
      'picture' : self.picture
    }



class Category(Base):
	__tablename__ = 'category'

	id = Column(Integer, primary_key = True)
	name = Column(String(100), nullable = False)
	user_id = Column(Integer, ForeignKey('user.id'))
	user = relationship(User)
	items = relationship("CategoryItem", backref="category", cascade="all, delete-orphan")

	@property
	def serialize(self):
		""" Return object data in easily serializeable format"""
		return {
			'id' : self.id,
      		'name' : self.name  ,
      		'user_id' : self.user_id
		}

class CategoryItem(Base):
	__tablename__ = 'categoryitem'

	id = Column(Integer, primary_key = True)
	name = Column(String(100), nullable = False)
	description = Column(String(250), nullable = False)
	user_id = Column(Integer, ForeignKey('user.id'))
	category_id = Column(Integer, ForeignKey('category.id'))
	#category= relationship(Category)
	user = relationship(User)


	@property
	def serialize(self):
		""" Return object data in easily serializeable format"""
		return {
			'id' : self.id,
      		'name' : self.name  ,
      		'description' : self.description,
      		'user_id' : self.user_id,
      		'category_id' : self.category_id
		}

engine = create_engine('sqlite:///catalogitemswithusers.db')
Base.metadata.create_all(engine)
