import { connect } from "mongoose";

const dbConnect = async () => {
  try {
    const mongoDbConnection = await connect(process.env.MONGODB_URI);
    console.log(`Database connected: ${mongoDbConnection.connection.host}`);
  } catch (error) {
    console.log(`Database connection failed ${error}`);
    process.exit(1);
  }
};
