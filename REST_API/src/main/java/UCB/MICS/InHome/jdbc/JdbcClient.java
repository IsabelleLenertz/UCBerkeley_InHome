package UCB.MICS.InHome.jdbc;

import com.google.common.collect.ImmutableList;

import javax.xml.transform.Result;
import java.sql.*;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;

import static UCB.MICS.InHome.jdbc.queries.*;

public class    JdbcClient {
    private final String dbUrl;
    private final String dbUser;
    private final String dbPwd;

    private final Connection connection;
    public JdbcClient() throws SQLException, ClassNotFoundException {
        dbUrl = System.getenv("DB_URL");
        dbUser = System.getenv("DB_USER");
        dbPwd = System.getenv("DB_PWD");
        //Class.forName("com.mysql.jdbc.Driver");
        connection =  DriverManager.getConnection(String.format("%s?user=%s&password=%s", dbUrl, dbUser, dbPwd));
    }

    public List<String> getDeviceNames() throws SQLException {
        ImmutableList.Builder<String> list = ImmutableList.builder();
        Statement statement = connection.createStatement();
        ResultSet res = statement.executeQuery("Select * from devices;");
        while(res.next()) {
            list.add(res.getString("Name"));
        }
        return list.build();
    }

    public boolean addDevice(String name, byte[] mac, byte[] ipv4) throws SQLException {
        connection.setAutoCommit(false);
        try(    PreparedStatement statement = connection.prepareStatement(INSERT_DEVICE, Statement.RETURN_GENERATED_KEYS);
                PreparedStatement statement2 = connection.prepareStatement(UPDATE_REVISIONS)){

            // Adding device to the table
            long now = LocalDateTime.now().toEpochSecond(ZoneOffset.UTC);
            statement.setString(1, name);
            statement.setBytes(2, mac);
            statement.setLong(3, now);
            statement.setBytes(4, ipv4);
            int deviceRows = statement.executeUpdate();

            // Updating revisions table
            statement2.setLong(1, now);
            int revisionRows = statement2.executeUpdate();

            // Confirming success, else rolling back transactions
            if (revisionRows != 1 || deviceRows != 1) {
                connection.rollback();
                return false;
            }
            else {
                connection.commit();
                return true;
            }
        }
        catch (SQLException e) {
            connection.rollback();
            throw e;
        }
        finally {
            connection.setAutoCommit(true);
        }
    }

    public boolean removeDevice(byte[] mac) throws SQLException {
        connection.setAutoCommit(false);
        try(    PreparedStatement removeStatement = connection.prepareStatement(DELETE_DEVICE);
                PreparedStatement removePolicyStatement = connection.prepareStatement("remove more");
                PreparedStatement updateRevisions = connection.prepareStatement(UPDATE_REVISIONS)) {

            // fill out statements
            removeStatement.setBytes(1, mac);
            int affected = removeStatement.executeUpdate();
            // test for errors
            connection.commit();
        }
        catch (SQLException e) {
            connection.rollback();
            throw e;
        }
        finally {
            connection.setAutoCommit(true);
        }
        return true;
    }
}