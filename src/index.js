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
    myTaskLists: [TaskList!]!
    getTaskList(id: ID!): TaskList!
  }

  type Mutation {
    signUp(input: SignUpInput!): AuthUser!
    signIn(input: SignInInput!): AuthUser!
    createTaskList(title: String!): TaskList!
    updateTaskList(id: ID!, title: String!): TaskList!
    deleteTaskList(id: ID!): Boolean!
    addUserToTaskList(taskListId: ID!, userId: ID!): TaskList!
  }
`;

const getToken = (user) => jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7 days'});
const getUserFromToken = async (token, db) => {
  if (!token) return null;
  const tokenData = jwt.verify(token, JWT_SECRET);
  if (!tokenData?.id) return null;
  return await db.collection('Users').findOne({ _id: ObjectId(tokenData.id) });
};

const resolvers = {
  Query: {
    myTaskLists: async (_, __, { db, user }) => {
      if (!user) throw new Error('Authentication error');
      return await db.collection('Tasks').find({ userIds: user._id }).toArray();
    },
    getTaskList: async (_, { id }, { db, user }) => {
      if (!user) throw new Error('Authentication error');

      return await db.collection('Tasks').findOne({ _id: ObjectId(id) });
    }
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
    },
    createTaskList: async (_, { title }, { db, user }) => {
      if (!user) throw new Error('Authentication error');

      const newTaskList = {
        title,
        createdAt: new Date().toISOString(),
        userIds: [user._id]
      }

      const result = await db.collection('Tasks').insertOne(newTaskList);
      const task = await db.collection('Tasks').findOne({ _id: result.insertedId })

      return task
    },
    updateTaskList: async (_, { id, title }, { db, user }) => {
      if (!user) throw new Error('Authentication error');
      
      const result = await db.collection('Tasks').findOneAndUpdate({ _id: ObjectId(id) }, { $set: { title } });
      return result.value;
    },
    deleteTaskList: async (_, { id }, { db, user }) => {
      if (!user) throw new Error('Authentication error');

      await db.collection('Tasks').deleteOne({ _id: ObjectId(id) });
      return true;
    },
    addUserToTaskList: async (_, { taskListId, userId }, { db, user }) => {
      if (!user) throw new Error('Authentication error');

      const task = await db.collection('Tasks').findOne({ _id: ObjectId(taskListId) });
      if (!task) return null;

      if (task.userIds.find((dbId) => dbId.toString() === userId.toString())) return task;

      await db.collection('Tasks').updateOne({ _id: ObjectId(taskListId) }, { $push: { userIds: ObjectId(userId) } });
      task.userIds.push(ObjectId(userId));
      return task;
    },
  },

  User: {
    id: ({ _id, id }) => _id || id
  },
  TaskList: {
    id: ({ _id, id }) => _id || id,
    progress: () => 0,
    users: async ({ userIds }, _, { db }) => Promise.all(userIds.map((userId) => db.collection('Users').findOne({ _id: userId })))
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