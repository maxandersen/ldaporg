///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS info.picocli:picocli:4.5.0
//DEPS org.apache.directory.api:api-all:2.1.0
//DEPS org.slf4j:slf4j-nop:1.7.32
//DEPS com.fasterxml.jackson.core:jackson-databind:2.12.4
//DEPS com.fasterxml.jackson.dataformat:jackson-dataformat-csv:2.12.4
//Deps to handle google profile search
//DEPS com.google.apis:google-api-services-people:v1-rev20200727-1.30.10
//DEPS com.google.oauth-client:google-oauth-client-jetty:1.23.0
//DEPS com.google.api-client:google-api-client:1.23.0
//JAVA 17

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.csv.CsvMapper;
import com.fasterxml.jackson.dataformat.csv.CsvSchema;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.store.FileDataStoreFactory;
import com.google.api.services.people.v1.PeopleService;
import com.google.api.services.people.v1.model.SearchDirectoryPeopleResponse;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Parameters;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.Callable;

import static java.lang.System.err;
import static java.lang.System.out;

@Command(name = "ldaporg", mixinStandardHelpOptions = true, version = "ldaporg 0.1",
        description = "ldaporg made with jbang")
class ldaporg implements Callable<Integer> {

    public static final String PHOTOS_CACHE = "photos.cache";
    @CommandLine.Option(names = { "--credentials" }, defaultValue = "credentials.json", description = "path to Google credentials")
    private File credentials;

    @CommandLine.Option(names="--photos", description = "Use Google to look up profile photos", defaultValue = "false")
    boolean findPhotos;

    private static final String APPLICATION_NAME = "clearpto";
    private static final JsonFactory JSON_FACTORY = JacksonFactory.getDefaultInstance();
    private static final String TOKENS_DIRECTORY_PATH = "tokens";
    private static final List<String> SCOPES = Collections.singletonList("https://www.googleapis.com/auth/directory.readonly");
    private PeopleService peopleService;

    Map<String, String> photoCache = new HashMap<>();

    private Credential getCredentials(final NetHttpTransport HTTP_TRANSPORT) throws IOException {
        // Load client secrets.
        InputStream in = new FileInputStream(credentials);

        GoogleClientSecrets clientSecrets = GoogleClientSecrets.load(JSON_FACTORY, new InputStreamReader(in));

        // Build flow and trigger user authorization request.
        GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow.Builder(HTTP_TRANSPORT, JSON_FACTORY,
                clientSecrets, SCOPES)
                .setDataStoreFactory(new FileDataStoreFactory(new java.io.File(TOKENS_DIRECTORY_PATH)))
                .setAccessType("offline").build();
        LocalServerReceiver receiver = new LocalServerReceiver.Builder().setPort(8888).build();
        return new AuthorizationCodeInstalledApp(flow, receiver).authorize("user");
    }

    String[]  fieldNames  = new String[] {"title", "manager", "rhatUUID", "rhatJobTitle", "cn", "rhatOfficeLocation", "uid"};
    final ObjectMapper mapper = new ObjectMapper().setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY);
    @Parameters(arity = "N", description = "The users to lookup", defaultValue = "")
    Set<String> users;
    @CommandLine.Option(names = {"-o", "--output"}, description = "Specify the CSV output filename")
    Path output;
    @CommandLine.Option(names = {"-i", "--infile"}, description = "Specify a file with email addreses")
    Path infile;

    public static void main(String... args) {
        int exitCode = new CommandLine(new ldaporg()).execute(args);
        System.exit(exitCode);
    }

    Optional<User> getUser(String id, LdapConnection connection, Map<String, User> users) {
        out.println("searching for " + id);

        try (EntryCursor cursor = connection.search("dc=redhat,dc=com",
                "(|(uid=" + id + ")(mail=" + id + ")(cn=" + id + "))",
                SearchScope.SUBTREE,
                fieldNames)) {

            if (cursor.next()) {
                var entry = cursor.get();
                var u = extractUser(connection, users, entry);
                out.println("Found " + u.get().dn);
                return u;
            } else {
                    out.println("Can't find user: " + id);
                }

            //cursor.forEach(out::println);
        } catch (LdapException | IOException | CursorException e) {
            throw new IllegalStateException(e);
        }
        return Optional.ofNullable(null);
    }

    private Optional<User> extractUser(LdapConnection connection, Map<String, User> users, Entry entry) throws CursorException {

        User u = extractUser(entry);

        u.count = 0;
        u.requested = true;
        u.primary = true;
        users.put(u.dn, u);
        if (u.manager != null) {
            if (!users.containsKey(u.manager)) {
                var mgr = getById(u.manager, connection, users);
                mgr.ifPresent(m -> u.superVisorId=m.uid);
            } else {
                incrementId(u.manager, users);
            }
        }

        return Optional.of(u);
    }

    /**
     * If all users roll up to a single user, then they will be removed from
     * the list when pruning.
     * This function increments the number of times a user rolls up into a supervisor
     * If all the users roll up into the same supervisor, they are safe to prune
     **/
    private void incrementId(String id, Map<String, User> users) {
        if(id == null) return;
        if(users.containsKey(id)) {
            var u = users.get(id);
            u.count++;
            if(!u.dn.equals(u.manager)) {
                incrementId(u.manager, users);
            }
        }
    }

    private User extractUser(org.apache.directory.api.ldap.model.entry.Entry entry) {
        Map<String, String> values = new HashMap<>();
        for (Attribute attribute : entry.getAttributes()) {
            values.put(attribute.getUpId(), attribute.get().getString());
        }
        User u = mapper.convertValue(values, User.class);
        u.dn = entry.getDn().toString();
        if(peopleService!=null) {
            List<String> sources = new ArrayList<>();
            sources.add("DIRECTORY_SOURCE_TYPE_DOMAIN_CONTACT");
            sources.add("DIRECTORY_SOURCE_TYPE_DOMAIN_PROFILE");

            String cachedUrl = photoCache.get(u.uid);

            if(cachedUrl!=null) {
                u.photoUrl = cachedUrl;
            } else {
                SearchDirectoryPeopleResponse result = null;
                out.println("Searching for photo for " + u.uid);
                int retries = 3;
                while(u.photoUrl==null && retries>0) {
                    retries--;

                    try {
                        result = peopleService.people().searchDirectoryPeople()
                                .setSources(sources).setQuery(u.uid).setReadMask("photos").execute();
                        if (result.getPeople() == null) {
                            err.println("Could not find photo for " + u.uid);
                        } else {
                            result.getPeople().stream().findFirst().ifPresent(p -> {
                                if (p.getPhotos() != null) {
                                    p.getPhotos().stream().findFirst().ifPresent(photo -> u.photoUrl = photo.getUrl());
                                    photoCache.put(u.uid, u.photoUrl);
                                }
                            });
                        }
                    } catch (IOException e) {
                        err.println("Problem fetching photo " + e.getMessage());
                        //e.printStackTrace();
                        if (e.getMessage().startsWith("429 Too Many")) {
                            if (retries > 0) {
                                err.println("Retrying " + retries);
                                try {
                                    Thread.sleep(10000);
                                } catch (InterruptedException ex) {
                                    ex.printStackTrace();
                                }
                            }
                        } else {
                            err.println("Giving up");
                        }
                    }
                }
            }
        }

        return u;
    }

    private Optional<User> getById(String dn, LdapConnection connection, Map<String, User> users) {
        if(users.containsKey(dn)) return Optional.of(users.get(dn));
        out.println("looking up by dn " + dn);
        try (EntryCursor cursor = connection.search(dn,
                "(objectclass=*)",
                SearchScope.SUBTREE,
                fieldNames)) {

            if (cursor.next()) {
                    User u = extractUser(cursor.get());
                    u.count=0;
                    users.put(u.dn,u);
                    if(u.manager !=null) {
                        if (!users.containsKey(u.manager)) {
                            var mgr = getById(u.manager, connection, users);
                            mgr.ifPresent(m -> u.superVisorId = u.uid);
                        } else {
                            incrementId(u.uid, users);
                        }
                    }
                    return Optional.of(u);
            }


        } catch (LdapException | CursorException | IOException e) {
            throw new IllegalStateException(e);
        }
        return Optional.ofNullable(null);
    }


    @Override
    public Integer call() throws Exception { // your business logic goes here...
        if(users.contains("-")) {
            users.clear();
            users.addAll(Arrays.asList(new String(System.in.readAllBytes(), StandardCharsets.UTF_8).split("\\r?\\n")));
        } else {
            users.clear();
            users.addAll(Files.readAllLines(infile));
        }

        if(findPhotos) {
            peopleService = getPeopleService();
            Properties p = new Properties();
            if(Path.of(PHOTOS_CACHE).toFile().exists()) {
                p.load(new FileReader(PHOTOS_CACHE));
            }
            p.forEach((k,v) -> photoCache.put((String)k,(String)v));
        }

        Map<String, User> resolvedUsers = new HashMap<>();
        try (var connection = new LdapNetworkConnection("ldap.corp.redhat.com")) {
            connection.bind();
            users.forEach(user -> getUser(user, connection, resolvedUsers));

            Map<String, User> copy = new HashMap<>(resolvedUsers);
            copy.forEach((k,u)-> {
                if(u.dn.equals(u.manager)) {
                    u.manager = null; // to have a root
                }
                if(u.manager ==null) return;
                var supervisor = getById(u.manager, connection, resolvedUsers);
                supervisor.ifPresentOrElse(su -> u.superVisorName=su.cn, () -> err.println("Could not find supervisor " + u.manager + " for " + u.uid));

            });
        }


        OutputStream os = System.out;
        if(output!=null){
            os = new FileOutputStream(output.toFile());
        }

        CsvMapper csvMapper = new CsvMapper();
        CsvSchema schema = csvMapper.schemaFor(User.class).withHeader();
        csvMapper.writer(schema)
                .writeValue(os, resolvedUsers.values());

        if(output!=null) {
            os.flush(); os.close();
        }

        if(!photoCache.isEmpty()) {
            Properties p = new Properties();
            p.putAll(photoCache);
            p.store(new FileWriter(PHOTOS_CACHE),"uuid to photo url cache");
        }


        return 0;
    }

    private PeopleService getPeopleService() throws GeneralSecurityException, IOException {
        PeopleService service = null;
        try {
            // Build a new authorized API client service.
            final NetHttpTransport HTTP_TRANSPORT = GoogleNetHttpTransport.newTrustedTransport();
            service = new PeopleService.Builder(HTTP_TRANSPORT, JSON_FACTORY, getCredentials(HTTP_TRANSPORT))
                    .setApplicationName(APPLICATION_NAME).build();
        } catch (FileNotFoundException fe) {
            err.println(fe);
            err.println(
                    "\nYou are missing credentials for accessing Google API's.\nDo the following:\n 1. Go to https://console.cloud.google.com/apis/library/people.googleapis.com\n 2. click 'Enable the Google People API'\n 3. Download credentials from https://console.cloud.google.com/apis/api/people.googleapis.com/credentials and put it in current working directory named as `credentials.json`.\n 4. run script again");
            return null;
        }
        return service;
    }

    public static class User {

        public String title;
        public String manager;
        public String rhatUUID;
        public String rhatJobTitle;
        public String cn;
        public String rhatOfficeLocation;
        public String dn;
        public boolean primary;
        public int count;
        public boolean requested;
        public String superVisorName;
        public String superVisorId;
        public String uid;
        public String photoUrl;

        @Override
        public String toString() {
            return "User{" +
                    "title='" + title + '\'' +
                    ", manager='" + manager + '\'' +
                    ", rhatOraclePersonID='" + rhatUUID + '\'' +
                    ", rhatJobTitle='" + rhatJobTitle + '\'' +
                    ", cn='" + cn + '\'' +
                    ", rhatOfficeLocation='" + rhatOfficeLocation + '\'' +
                    ", primary=" + primary +
                    ", count=" + count +
                    ", requested=" + requested +
                    '}';
        }
    }
}
