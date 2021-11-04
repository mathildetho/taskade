const { ApolloServer, gql } = require('apollo-server');
const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
dotenv.config();
const { DB_URI, DB_NAME, JWT_SECRET } = process.env;

const typeDefs = gql`
  type User {
    id: ID!
    name: String!
    email: String!
    avatar: String
  }

  type TaskList {
    id: ID!
    createdAt: String!
    title: String!
    progress: Float!
    users: [User!]!
    todos: [Todo!]!
  }

  type Todo {
    id: ID!
    content: String!
    isCompleted: Boolean!
    taskList: TaskList!
  }

  type AuthUser {
    user: User!
    token: String!
  }

  input SignUpInput {
    email: String!
    password: String!
    name: String!
    avatar: String
  }

  input SignInInput {
    email: String!
    password: String!
  }

  type Query {
    myTaskList: [TaskList!]!
  }

  type Mutation {
    signUp(input: SignUpInput): AuthUser!
    signIn(input: SignInInput): AuthUser!
  }
`;

const getToken = (user) => jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '7 days'});
const getUserFromToken = async (token, db) => {
  if (!token) return null;
  const tokenData = jwt.verify(token, JWT_SECRET);
  if (!tokenData?.id) return null;
  return await db.collection('Users').findOne({ _id: ObjectId(tokenData.id) });
};

const resolvers = {
  Query: {
    myTaskList: () => []
  },
  Mutation: {
    signUp: async (_, { input }, { db }) => {
      const hashedPassword = bcrypt.hashSync(input.password);
      const newUser = {
        ...input,
        password: hashedPassword
      };
      
      const result= await db.collection('Users').insertOne(newUser);
      const user = await db.collection('Users').findOne({ _id: result.insertedId })
      
      return {
        user,
        token: getToken(user)
      }
    },
    signIn: async (_, { input }, { db }) => {
      const user = await db.collection('Users').findOne({ email: input.email });
      const isPasswordCorrect = user && bcrypt.compareSync(input.password, user.password);

      if (!user || !isPasswordCorrect) {
        throw new Error('Invalid credentials');
      }

      return {
        user,
        token: getToken(user)
      }
    }
  },

  User: {
    id: ({ _id, id }) => _id || id
  }
};

const start = async () => {
  const client = new MongoClient(DB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
  await client.connect();
  const db = client.db(DB_NAME);

  const server = new ApolloServer({
    typeDefs,
    resolvers,
    context: async ({ req }) => {
      const user = await getUserFromToken(req.headers.authorization, db);
      return {
        db,
        user
      }
    }
  });
  server.listen().then(({ url }) => {
    console.log(`🚀  Server ready at ${url}`);
  });
};

start();