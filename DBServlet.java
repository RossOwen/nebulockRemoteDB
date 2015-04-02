import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.SQLException;
import java.util.Collection;

import org.json.*;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.io.UnsupportedEncodingException;

import java.security.SecureRandom;
import java.math.BigInteger;

public class DBServlet extends HttpServlet {

    private static final long serialVersionUID = -3388076538168097844L;
    
    private Connection conn;
    
    public void initDB() throws SQLException, IllegalAccessException, InstantiationException, ClassNotFoundException
    {
        String url = "jdbc:mysql://hbgwebfe.hbg.psu.edu/nebulock";
        String driver = "com.mysql.jdbc.Driver";
        String userName = "rmo5087";
        String password = "4636";
        
        Class.forName(driver).newInstance();
        conn = DriverManager.getConnection(url,userName,password);
    }

    public DBServlet() throws IllegalAccessException, InstantiationException, ClassNotFoundException, SQLException
    {
        initDB();
    }
    
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        // SECURITY WARNING:  In order to protect the confidentiality of the password, this communication 
        // should occur over an encrypted https connection, using additional parameters that establish the user's identity, AND
        // using POST not get

        // For demonstration purposes, we will submit all requests using the Get method

        resp.setBufferSize(8 * 1024); // 8K buffer
        resp.setContentType("text/html");

				System.out.println(req.getRequestURI());
            
        if (req.getRequestURI().equalsIgnoreCase("/bin/getAccount"))
        {
             doGetAccount(req,resp);
        }
        else if (req.getRequestURI().equalsIgnoreCase("/bin/createAccount"))
        {
             doCreateAccount(req,resp);
        }
        else if (req.getRequestURI().equalsIgnoreCase("/bin/updateAccount"))
        {
             doUpdateAccount(req,resp);
        }
        else if (req.getRequestURI().equalsIgnoreCase("/bin/deleteAccount"))
        {
             doDeleteAccount(req,resp);
        }
        else if (req.getRequestURI().equalsIgnoreCase("/bin/login")){
             doLogin(req,resp);
        }
        else if (req.getRequestURI().equalsIgnoreCase("/bin/doCreateVault")){
             doCreateVault(req,resp);
        }
        else if (req.getRequestURI().equalsIgnoreCase("/bin/doGetVaults")){
             doGetVaults(req,resp);
        }
        else if(req.getRequestURI().equalsIgnoreCase("/bin/doGetEntries")){
             doGetEntries(req,resp);
        }
        else if(req.getRequestURI().equalsIgnoreCase("/bin/doCreateEntry")){
             doCreateEntry(req,resp);
        }
        else {
             resp.getWriter().println("INVALID REQUEST");
        }
    }
    
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException
    {
    }

    private void doGetAccount(HttpServletRequest req, HttpServletResponse resp) throws IOException
    {    
        PrintWriter out = resp.getWriter();
        try
        {
            String query = "SELECT email FROM Accounts "; 
            String where = "";
            if (req.getParameter("email") != null) {
                where = " WHERE email = ?";
            }

            PreparedStatement statement = conn.prepareStatement(query + where);

            // Debugging
            System.out.println(req.getParameter("email"));
            System.out.println(query + where);

            if (req.getParameter("email") != null) { 
                statement.setString(1,req.getParameter("email"));
            }

            ResultSet resultSet = statement.executeQuery();
            StringBuffer sb = new StringBuffer();
            sb.append("{");
            sb.append("  \"result\":\"success\",");
            sb.append("  \"records\":[");
            boolean firstRec = true;
            while (resultSet.next()) //TODO: This is where we encode the table result (one loop for each row)
            {
                if (firstRec) firstRec = false;
                else
                    sb.append("              ,");
                //sb.append("              { \"accountID\":" + resultSet.getInt("accountID") + ",");
                sb.append("{\"email\":\"" + resultSet.getString("email") + "\"}");
            }
            sb.append("]");
            sb.append("}");
            // Debugging
            System.out.println(sb);
            out.println(sb);
       }
        catch (SQLException e)
        {
            out.println("{\"result\":\"failure\"}");
            System.err.println(e);
            e.printStackTrace();
        }
    }

    private void doCreateAccount(HttpServletRequest req, HttpServletResponse resp) throws IOException
    {    
        PrintWriter out = resp.getWriter();
        try
        {
            String email = req.getParameter("email");
            String password = req.getParameter("password");

            String salt = nextSessionId();
            System.out.println("Salt for " + email + ": " + salt);
						System.out.println("Hash for " + email + ": " + new String(getHash(password + salt)));
						System.out.println("pwd for " + email + ": " + password);

            PreparedStatement statement = conn.prepareStatement("INSERT INTO Accounts (email, pwdhash, salt) VALUES(?,?,?)");
            statement.setString(1,req.getParameter("email"));
            statement.setString(2,new String(getHash(password + salt)));
            statement.setString(3,salt);

            int updated = statement.executeUpdate();
            if (updated == 1)
                out.println("{\"result\":\"success\"}");
            else
                out.println("{\"result\":\"failure\"}");
        }
        catch (Exception e)
        {
            out.println("{\"result\":\"failure\"}");
            System.err.println(e);
            e.printStackTrace();
        }

    }

private void doLogin(HttpServletRequest req, HttpServletResponse resp) throws IOException
    {    
        PrintWriter out = resp.getWriter();
        try
        {
            String email = req.getParameter("email");
            String password = req.getParameter("password");
            String salt = "";

            PreparedStatement saltStatement = conn.prepareStatement("SELECT salt FROM Accounts WHERE email = ?");
            saltStatement.setString(1,req.getParameter("email"));
            ResultSet saltResultSet = saltStatement.executeQuery();

            if(saltResultSet.first()){
                salt = saltResultSet.getString("salt");
                System.out.println(salt);
            } else{
                //debugging
                sendFailure(out, "NO SUCH ACCOUNT", null);
                return;
            }

            //debugging
            System.out.println("Salt: " + salt);

            String pwdhash = new String(getHash(password + salt));
            System.out.println("Hash: " + pwdhash);
						System.out.println("PWD: " + password);

            PreparedStatement statement = conn.prepareStatement("SELECT accountID FROM Accounts WHERE email = ? AND pwdhash = ?");
            statement.setString(1,req.getParameter("email"));
            statement.setString(2,pwdhash);


            //statement.setString(3,salt);

            
            System.out.println(email + " " + password);
            System.out.println("Password hash: " + pwdhash);

            ResultSet resultSet = statement.executeQuery();
            StringBuffer sb = new StringBuffer();
            sb.append("{");
            sb.append("  \"result\":\"success\",");
            sb.append("  \"records\":[");
            boolean firstRec = true;

						if (!resultSet.next() ) {
							sendFailure(out, "Invalid credentials", null);
						}
            else {


							sendSuccess(out, new JSONObject(resultSet.getInt("accountID")));
							
                sb.append("              ,");
                //sb.append("              { \"accountID\":" + resultSet.getInt("accountID") + ",");
                sb.append("{\"accountID\":\"" + resultSet.getInt("accountID") + "\"}");
            }
            sb.append("]");
            sb.append("}");
            //out.println(sb);
           //debugging
            System.out.println(sb);
        }
        catch (Exception e)
        {
            //debugging
            System.out.println("FAILURE");
            out.println("{\"result\":\"failure\"}");
            System.err.println(e);
            e.printStackTrace();
        }

    }


    //TODO:
    private void doUpdateAccount(HttpServletRequest req, HttpServletResponse resp) throws IOException
    {    
        PrintWriter out = resp.getWriter();
        try
        {

            PreparedStatement statement = conn.prepareStatement("UPDATE Course SET prefix=?, suffix=?, credits=? WHERE id=?");
            statement.setString(1,req.getParameter("prefix"));
            statement.setString(2,req.getParameter("suffix"));
	    statement.setString(3,req.getParameter("credits"));
            statement.setString(4,req.getParameter("id"));

            int updated = statement.executeUpdate();
            if (updated == 1)
                out.println("{\"result\":\"success\"}");
            else
                out.println("{\"result\":\"failure\"}");
        }
        catch (SQLException e)
        {
            out.println("{\"result\":\"failure\"}");
            System.err.println(e);
            e.printStackTrace();
        }
    }

    //TODO:
    private void doDeleteAccount(HttpServletRequest req, HttpServletResponse resp) throws IOException
    {    
        PrintWriter out = resp.getWriter();
        try
        {

            PreparedStatement statement = conn.prepareStatement("DELETE FROM Course WHERE id=?");
            statement.setString(1,req.getParameter("id"));

            int updated = statement.executeUpdate();
            if (updated == 1)
                out.println("{\"result\":\"success\"}");
            else
                out.println("{\"result\":\"failure\"}");
        }
        catch (SQLException e)
        {
            out.println("{\"result\":\"failure\"}");
            System.err.println(e);
            e.printStackTrace();
        }
    }

    private void doCreateVault(HttpServletRequest req, HttpServletResponse resp) throws IOException
    {    
        PrintWriter out = resp.getWriter();
        try
        {
            String email = req.getParameter("email");
            String password = req.getParameter("password");
						String vaultName = req.getParameter("vaultName");
						String vaultDescription = req.getParameter("vaultDescription");

            System.err.println(email);
            System.err.println(password);
						System.err.println(vaultName);
						System.err.println(vaultDescription);
						
						
						int accountID = -1; 
						if((accountID = authenticateAndReturnAccountID(email, password)) != -1) {

		          PreparedStatement statement = conn.prepareStatement("INSERT INTO Vaults (accountID, vaultName, vaultDescription) VALUES(?,?,?)");
		          statement.setInt(1, accountID);
		          statement.setString(2, vaultName);
							statement.setString(3, vaultDescription);
            int updated = statement.executeUpdate();

            if (updated == 1)
                out.println("{\"result\":\"success\"}");
            else
                sendFailure(out, "derp", null);

					} else {

							sendFailure(out, "Invalid password", null);

					}
        }
        catch (Exception e)
        {
 						sendError(out, "The server was unable to proccess your request. Try again later!", null);

						e.printStackTrace();
        }

    }


		private void doGetVaults(HttpServletRequest req, HttpServletResponse resp) throws IOException
    {    
        PrintWriter out = resp.getWriter();
        try
        {
            String email = req.getParameter("email");
            String password = req.getParameter("password");
						
						int accountID = -1; 
						if((accountID = authenticateAndReturnAccountID(email, password)) != -1) {

		          PreparedStatement preparedStatement = conn.prepareStatement("SELECT * FROM Vaults WHERE accountID = ?");
		          preparedStatement.setInt(1, accountID);

							ResultSet rs = preparedStatement.executeQuery();

							JSONObject retval = new JSONObject();
							JSONArray vaults = new JSONArray();

							while (rs.next()) {
								
								JSONObject vault = new JSONObject();

								vault.put("vaultID",  rs.getInt("vaultID"));
								vault.put("vaultName",  rs.getString("vaultName"));
								vault.put("vaultDescription",  rs.getString("vaultDescription"));

								vaults.put(vault);		
															
							}

							retval.put("vaults" , vaults);

							sendSuccess(out, retval);

						} else {

							sendFailure(out, "Failed to authenticate.", null);

						}
        }
        catch (Exception e)
        {
 						sendError(out, "The server was unable to proccess your request. Try again later!",null);

						e.printStackTrace();
        }

    }

    private void doCreateEntry(HttpServletRequest req, HttpServletResponse resp) throws IOException
    {    
        PrintWriter out = resp.getWriter();
        try
        {
            String email = req.getParameter("email");
            String password = req.getParameter("password");
						int vaultID = java.lang.Integer.parseInt(req.getParameter("vaultID"));
						String entryName = req.getParameter("entryName");
            String text = req.getParameter("text");

            System.err.println(email);
            System.err.println(password);
						System.err.println(vaultID);
            System.err.println(entryName);
						System.err.println(text);
						
						
						int accountID = -1; 
						if((accountID = authenticateAndReturnAccountID(email, password)) != -1) {

		          PreparedStatement statement = conn.prepareStatement("INSERT INTO Entries (vaultID, emailCreatedBy, entryName, text) VALUES(?,?,?,?)");
		          statement.setInt(1, vaultID);
              statement.setString(2, email);
		          statement.setString(3, entryName);
							statement.setString(4, text);
              int updated = statement.executeUpdate();

              if (updated == 1)
                  out.println("{\"result\":\"success\"}");
              else
                  sendFailure(out, "derp", null);

					  } else {

							  sendFailure(out, "Invalid password", null);

					  }
        }
        catch (Exception e)
        {
 						sendError(out, "The server was unable to process your request. Try again later!", null);

						e.printStackTrace();
        }

    }
    private void doGetEntries(HttpServletRequest req, HttpServletResponse resp) throws IOException
    {    
        PrintWriter out = resp.getWriter();
        try
        {
            int vaultID = java.lang.Integer.parseInt(req.getParameter("vaultID"));

		        PreparedStatement preparedStatement = conn.prepareStatement("SELECT * FROM Entries WHERE vaultID = ?");
		        preparedStatement.setInt(1, vaultID);

						ResultSet rs = preparedStatement.executeQuery();

						JSONObject retval = new JSONObject();
						JSONArray entries = new JSONArray();

						while (rs.next()) {
								
							JSONObject entry = new JSONObject();

							entry.put("vaultID",  rs.getInt("vaultID"));
							entry.put("emailCreatedBy",  rs.getString("emailCreatedBy"));
							entry.put("entryName",  rs.getString("entryName"));
							entry.put("text",  rs.getString("text"));

							entries.put(entry);		
															
						}

						retval.put("entries" , entries);

						sendSuccess(out, retval);
        }
        catch (Exception e)
        {
 						sendError(out, "The server was unable to proccess your request. Try again later!",null);

						e.printStackTrace();
        }

    }

    public byte[] getHash(String password) throws Exception {
      MessageDigest digest = MessageDigest.getInstance("SHA-512");
      digest.reset();
      byte[] input = digest.digest(password.getBytes("UTF-8"));
      return input;
    }

		//TODO: Make second parameter a JSON object and append its parse to data
		private void sendSuccess(PrintWriter stream, JSONObject data) {

				System.out.println(data);
				stream.println("{");
				stream.println("\tresult : \"success\",\n");
				stream.println("\tdata : " + data);
				stream.println("}");

		}

		private void sendFailure(PrintWriter stream, String errorMessage, JSONObject data) {

				System.out.println(errorMessage);
				stream.println("{");
				stream.println("\tresult : \"failure\",\n");
				stream.println("\tmessage : \"" + errorMessage + "\"");
				stream.println("}");
		}

		private void sendError(PrintWriter stream, String errorMessage,JSONObject data) {

				System.out.println(errorMessage);
				stream.println("{");
				stream.println("\tresult : \"error\",\n");
				stream.println("\tmessage : \"" + errorMessage + "\"");
				stream.println("\tdata : \"" + data + "\"");
				stream.println("}");

		}


		public int authenticateAndReturnAccountID (String email, String password) throws Exception{

            String salt = "";

            PreparedStatement saltStatement = conn.prepareStatement("SELECT salt FROM Accounts WHERE email = ?");

            saltStatement.setString(1,email);
            ResultSet saltResultSet = saltStatement.executeQuery();

            if(saltResultSet.first()){

                salt = saltResultSet.getString("salt");

            } else{

                return -1;
            }

            String pwdhash = new String(getHash(password + salt));

            PreparedStatement statement = conn.prepareStatement("SELECT accountID FROM Accounts WHERE email = ? AND pwdhash = ?");
            statement.setString(1,email);
            statement.setString(2,new String(getHash(password + salt)));

            ResultSet resultSet = statement.executeQuery();

            if (!resultSet.next()) return -1;

					return resultSet.getInt("accountID");

		}

		public boolean isLockedOut (int accountID){return false;}



    public String nextSessionId() {
      return new BigInteger(130, new SecureRandom()).toString(32);
    }
    

}
