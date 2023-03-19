package UCB.MICS.InHome.jdbc;

import UCB.MICS.InHome.Utilities;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;

import javax.xml.transform.Result;
import java.sql.*;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import static UCB.MICS.InHome.Utilities.*;
import static UCB.MICS.InHome.jdbc.queries.*;

public class    JdbcClient {
    private final String dbUrl;
    private final String dbUser;
    private final String dbPwd;
    private final static Logger logger = Logger.getLogger(JdbcClient.class.toString());
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
        ResultSet res = statement.executeQuery(SELECT_ALL_DEVICES);
        while(res.next()) {
            list.add(res.getString("Name"));
        }
        return list.build();
    }

    public List<Map<String, String>> getAllDevices() throws SQLException
    {
        ImmutableList.Builder listBuilder = ImmutableList.builder();
        try (PreparedStatement statement = connection.prepareStatement(SELECT_ALL_DEVICES)) {
            ResultSet results = statement.executeQuery();
            while(results.next()) {
                listBuilder.add(
                        Map.of(
                            NAME, results.getString("Name"),
                            IPV4, byteArrayIpv4ToString(results.getBytes("Ipv4")),
                            IPV6, byteArrayIpv6ToString(results.getBytes("Ipv6")),
                            DATE_ADDED, results.getString("dateAdded"), // TODO: convert the long to legible date
                            MAC, byteArrayMacToString(results.getBytes("Mac")),
                            IS_TRUSTED, String.valueOf(results.getBoolean("isTrusted"))
                        ));
            }
        }
        catch (SQLException e) {
            throw e;
        }
        return listBuilder.build();
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
        try (   PreparedStatement removeStatement = connection.prepareStatement(DELETE_DEVICE);
                PreparedStatement removePolicyStatement = connection.prepareStatement(DELETE_POLICY);
                PreparedStatement updateRevisions = connection.prepareStatement(UPDATE_REVISIONS)) {

            long now = LocalDateTime.now().toEpochSecond(ZoneOffset.UTC);
            // fill out statements
            // Remove the device
            removeStatement.setBytes(1, mac);
            int affected = removeStatement.executeUpdate();

            // Remove the policies
            removePolicyStatement.setBytes(1, mac);
            removePolicyStatement.setBytes(2, mac);
            int affectedPolicies = removePolicyStatement.executeUpdate();


            // Update the revision table
            updateRevisions.setLong(1, now);
            int revisions = updateRevisions.executeUpdate();
            // test for errors
            if(revisions != 1 || affected != 1 || affectedPolicies != 1) {
                connection.rollback();
                return false;
            }
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

    public boolean updateName(String oldName, String newName) throws SQLException
    {
        connection.setAutoCommit(false);
        try(PreparedStatement updateName = connection.prepareStatement(UPDATE_NAME);
            PreparedStatement updateRevisions = connection.prepareStatement(UPDATE_REVISIONS)) {

            // Update device table
            updateName.setString(1, oldName);
            updateName.setString(2, newName);
            int affected = updateName.executeUpdate();

            // Update revision table
            updateRevisions.setLong(1, LocalDateTime.now().toEpochSecond(ZoneOffset.UTC));
            int revisions = updateRevisions.executeUpdate();

            // test for errors
            if(revisions != 1 || affected != 1) {
                connection.rollback();
                return false;
            }
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

    public Map<String, String> getOneDevice(byte[] mac) throws SQLException {
        ImmutableList.Builder listBuilder = ImmutableList.builder();
        try (PreparedStatement statement = connection.prepareStatement(GET_ONE_DEVICE)) {
            // Populate prepared statement
            statement.setBytes(1, mac);
            ResultSet results = statement.executeQuery();
            while(results.next()) {
                listBuilder.add(
                        Map.of(
                                NAME, results.getString("Name"),
                                IPV4, byteArrayIpv4ToString(results.getBytes("Ipv4")),
                                IPV6, byteArrayIpv6ToString(results.getBytes("Ipv6")),
                                DATE_ADDED, results.getString("dateAdded"), // TODO: convert the long to legible date
                                MAC, byteArrayMacToString(results.getBytes("Mac")),
                                IS_TRUSTED, String.valueOf(results.getBoolean("isTrusted"))
                        ));
            }
        } catch (SQLException e) {
            throw e;
        }
        List<Map<String, String>> list = listBuilder.build();
        if(list.size() != 1) {
            return Map.of();
        }
        return list.get(0);
    }
    
    public boolean updatePolicy(String fromName, String toName) throws SQLException
    {
        byte[] macFrom;
        byte[] macTo;
        connection.setAutoCommit(false);
        try(PreparedStatement getMacFrom = connection.prepareStatement(GET_MAC_FROM_NAME);
            PreparedStatement getMacTo = connection.prepareStatement(GET_MAC_FROM_NAME);
            PreparedStatement updatePolicies = connection.prepareStatement(UPDATE_POLICIES);
            PreparedStatement updateRevisions = connection.prepareStatement(UPDATE_REVISIONS)) {


            getMacTo.setString(1, toName);
            ResultSet resultsTo = getMacTo.executeQuery();

            if(resultsTo.next()){
                macTo = resultsTo.getBytes("mac");
                getMacFrom.setString(1, fromName);
                ResultSet resultsFrom = getMacFrom.executeQuery();
                if(resultsFrom.next()){
                    macFrom = resultsFrom.getBytes("mac");
                }
                else{
                    return false;
                }
            }
            else{
                return false;
            }
            
            // Update device table
            updatePolicies.setBytes(1, macTo);
            updatePolicies.setBytes(2, macFrom);
            int affected = updatePolicies.executeUpdate();

            // Update revision table
            updateRevisions.setLong(1, LocalDateTime.now().toEpochSecond(ZoneOffset.UTC));
            int revisions = updateRevisions.executeUpdate();

            // test for errors
            if(revisions != 1 || affected != 1) {
                connection.rollback();
                return false;
            }
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

    public List<Map<String, String>> getAllPolicies() throws SQLException
    {
        ImmutableList.Builder listBuilder = ImmutableList.builder();
        try (PreparedStatement statement = connection.prepareStatement(GET_ALL_POLICIES)) {
            ResultSet results = statement.executeQuery();
            while(results.next()) {
                byte[] macFrom = results.getBytes("deviceFrom");
                byte[] macTo = results.getBytes("deviceTo");
                String nameTo;
                String nameFrom;
                try(PreparedStatement to = connection.prepareStatement(GET_NAME_FROM_ONE_MAC);
                    PreparedStatement from = connection.prepareStatement(GET_NAME_FROM_ONE_MAC)) {
                    to.setBytes(1, macTo);
                    from.setBytes(1, macFrom);
                    ResultSet resTo = to.executeQuery();
                    ResultSet resFrom = from.executeQuery();
                    if (resFrom.next()) {
                        nameFrom = resFrom.getString(NAME);
                    } else {
                        throw new SQLException();
                    }
                    if(resTo.next()) {
                        nameTo = resTo.getString(NAME);
                    } else {
                        throw new SQLException();
                    }
                }
                listBuilder.add(
                        Map.of(
                                "policyId", results.getInt("policyId"),
                                "deviceTo", nameTo,
                                "deviceFrom", nameFrom
                        ));
            }
        }
        return listBuilder.build();
    }

    public List<Map<String, String>> getAllPoliciesFromName(String name) throws SQLException {
        ImmutableList.Builder<Map<String, String>> listBuilder = ImmutableList.builder();
        try (PreparedStatement getMac = connection.prepareStatement(GET_MAC_FROM_NAME);
             PreparedStatement statement = connection.prepareStatement(GET_POLICY_BY_DEVICE_ANY);
             PreparedStatement getNames = connection.prepareStatement(GET_NAME_FROM_MAC);) {
            // Populate prepared statement

            getMac.setString(1, name);
            ResultSet results = getMac.executeQuery();
            while(results.next()) {
                statement.setBytes(1, results.getBytes("Mac"));
                statement.setBytes(2, results.getBytes("Mac"));
                ResultSet resultPolicy = statement.executeQuery();
                while(resultPolicy.next()) {
                    getNames.setBytes(1, resultPolicy.getBytes("deviceTo"));
                    getNames.setBytes(2, resultPolicy.getBytes("deviceFrom"));
                    ResultSet resultNames = getNames.executeQuery();
                    while(resultNames.next()){
                        String rName = resultNames.getString("Name");
                        String rMac = Utilities.byteArrayMacToString(resultNames.getBytes("Mac"));
                        String rIp = Utilities.byteArrayIpv4ToString(resultNames.getBytes("Ipv4"));
                        if(!rName.isEmpty() && !rName.equalsIgnoreCase(name)){
                            Map<String, String> map = ImmutableMap.of(NAME, rName,
                                    MAC, rMac,
                                    IPV4, rIp);
                            listBuilder.add(map);
                        }
                    }
                }
            }
        }
        return listBuilder.build();
    }

    public boolean removeByPolicyId(int pid) throws SQLException {
        connection.setAutoCommit(false);
        try (   PreparedStatement removeStatement = connection.prepareStatement(DELETE_BY_POLICY_ID);
                PreparedStatement updateRevisions = connection.prepareStatement(UPDATE_REVISIONS)) {

            long now = LocalDateTime.now().toEpochSecond(ZoneOffset.UTC);
            // fill out statements
            // Remove the device
            removeStatement.setInt(1, pid);
            int affected = removeStatement.executeUpdate();

            // Update the revision table
            updateRevisions.setLong(1, now);
            int revisions = updateRevisions.executeUpdate();
            // test for errors
            if(revisions != 1 || affected != 1) {
                connection.rollback();
                return false;
            }
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
