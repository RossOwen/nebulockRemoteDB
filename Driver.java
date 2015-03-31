import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.HandlerList;
import org.eclipse.jetty.server.handler.ResourceHandler;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
 
public class Driver 
{
 
    public static void main(String[] args) throws Exception
    {
        Server server = new Server(6917);
        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
        context.setContextPath("/bin");
       
        ResourceHandler resource_handler = new ResourceHandler();
        resource_handler.setDirectoriesListed(false);
        resource_handler.setResourceBase("./data");
       
        HandlerList handlers = new HandlerList();
        handlers.setHandlers(new Handler[] { resource_handler, context });
        server.setHandler(handlers);
        
        // Uses longest match logic on PathSpec
        context.addServlet(new ServletHolder(new DBServlet()),"/*");
 
        server.start();
        server.join();
    }
}
