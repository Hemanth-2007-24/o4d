const { Sequelize, DataTypes } = require('sequelize');
require('dotenv').config();

const sequelize = new Sequelize(process.env.DATABASE_URL, {
    logging: false, // Set to console.log to see SQL queries
});

const User = sequelize.define('User', {
    googleId: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
    },
    displayName: {
        type: DataTypes.STRING,
    },
    email: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
    },
    accessToken: {
        type: DataTypes.STRING(1024), // Access tokens can be long
        allowNull: false,
    },
    refreshToken: {
        type: DataTypes.STRING(1024), // Refresh tokens are also long
        allowNull: true, // May not always get one if user already authorized offline access
    },
});

const Site = sequelize.define('Site', {
    userId: {
        type: DataTypes.INTEGER,
        allowNull: false,
        references: {
            model: User,
            key: 'id',
        },
    },
    siteName: { // This will be the subdomain prefix
        type: DataTypes.STRING,
        allowNull: false,
        unique: true, // Important for subdomain uniqueness
    },
    driveFolderId: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    driveFolderName: {
        type: DataTypes.STRING,
    },
    // We can add customDomain later if needed for mapping true custom domains
});

User.hasMany(Site, { foreignKey: 'userId' });
Site.belongsTo(User, { foreignKey: 'userId' });

async function syncDatabase() {
    try {
        await sequelize.authenticate();
        console.log('Database connection has been established successfully.');
        await sequelize.sync({ alter: true }); // { force: true } for dev to drop tables
        console.log('All models were synchronized successfully.');
    } catch (error) {
        console.error('Unable to connect to the database or sync models:', error);
        process.exit(1); // Exit if DB connection fails
    }
}

module.exports = {
    sequelize,
    User,
    Site,
    syncDatabase,
};