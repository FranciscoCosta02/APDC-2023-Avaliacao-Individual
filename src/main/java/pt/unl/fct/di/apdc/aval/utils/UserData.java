package pt.unl.fct.di.apdc.aval.utils;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import java.util.regex.Pattern;

public class UserData {

    public String username;
    public String password;
    public String confirmation;
    public String email;
    public String name;

    public UserData(){}
    public UserData(String username, String email, String name, String password, String confirmation) {
        this.username = username;
        this.password = password;
        this.confirmation = confirmation;
        this.email=email;
        this.name = name;
    }

    public boolean confirmInputs() {
        return checkNull(username) || checkNull(password) || checkNull(email) || checkNull(name);
    }

    public boolean checkNull(String word){
        return word.isEmpty() || word == null;
    }

    public boolean emailValid() {
        String[] e = email.split("@");
        if(e.length != 2) return false;
        String domain = e[1];
        String[] d = domain.split("\\.");
        return !checkNull(d[d.length-1]);
    }

    public Response pwdValid() {
        Pattern specialChars = Pattern.compile("[^a-z0-9 ]", Pattern.CASE_INSENSITIVE);
        Pattern upperCase = Pattern.compile("[A-Z ]");
        Pattern digitCase = Pattern.compile("[0-9 ]");
        if(!password.equals(confirmation))
            return Response.status(Status.NOT_ACCEPTABLE)
                    .entity("Passwords do not match").build();
        if(password.length() < 7)
            return Response.status(Status.NOT_ACCEPTABLE)
                    .entity("Password length must be at least 7 characters").build();
        if(!specialChars.matcher(password).find())
            return Response.status(Status.NOT_ACCEPTABLE)
                    .entity("Password must have at least 1 special character").build();
        if(!upperCase.matcher(password).find())
            return Response.status(Status.NOT_ACCEPTABLE)
                    .entity("Password must have at least 1 upper case character").build();
        if(!digitCase.matcher(password).find())
            return Response.status(Status.NOT_ACCEPTABLE)
                    .entity("Password must have at least 1 digit character").build();
        return Response.ok().entity("Password is valid").build();
    }
}
