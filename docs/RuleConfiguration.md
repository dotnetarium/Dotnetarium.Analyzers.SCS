# YAML Configuration
You need to modify the `Config/Main.yml` file to add new entry points, sources, sinks and/or sanitizers.
Looks scary, but try to find a suitable example in the file and reuse it. 

Some attempt to provide some samples and exlain usage is below.

## Entry Points

Define entry points to specify where untrusted data can enter your application. Here's an example configuration:
```yml
TaintEntryPoints:
  System.Object:
    Dependency:
      - Microsoft.AspNetCore.Mvc.ControllerBase
      - Microsoft.AspNetCore.Mvc.ApiControllerAttribute
      - Microsoft.AspNetCore.Mvc.ControllerAttribute
      - Microsoft.AspNetCore.Mvc.NonControllerAttribute
      - Microsoft.AspNetCore.Mvc.NonActionAttribute
      - Microsoft.AspNetCore.Mvc.FromServicesAttribute
    Class:
      Accessibility:
        - public
      Suffix:
        Text: Controller
        IncludeParent: true
      Attributes:
        Include:
          - Type: Microsoft.AspNetCore.Mvc.ControllerAttribute
          - Type: Microsoft.AspNetCore.Mvc.ApiControllerAttribute
        Exclude:
          - Type: Microsoft.AspNetCore.Mvc.NonControllerAttribute
    Method:
      Accessibility:
        - public
      IncludeConstructor: false
      Static: false
      Attributes:
        Exclude:
          - Type: Microsoft.AspNetCore.Mvc.NonActionAttribute
    Parameter:
      Attributes:
        Exclude:
          - Type: Microsoft.AspNetCore.Mvc.FromServicesAttribute

```

- `System.Object`: The root object type for defining entry points.
- `Dependency`: Specifies dependencies that indicate the presence of an entry point.
  - `Microsoft.AspNetCore.Mvc.ControllerBase`: Indicates dependency on `ControllerBase`.
  - `Microsoft.AspNetCore.Mvc.ApiControllerAttribute`: Indicates the use of `ApiControllerAttribute`.
  - Other attributes specify additional dependencies or attributes to consider.
- `Class`: Specifies criteria for class-level entry points.
  - `Accessibility`: Defines accessibility levels, e.g., `public`.
  - `Suffix`: Criteria based on class name suffix.
    - `Text`: The suffix text, e.g., `Controller`.
    - `IncludeParent`: Whether to include parent classes.
  - `Attributes`: Specifies attributes to include or exclude.
    - `Include`: Attributes to include, e.g., `ControllerAttribute`.
    - `Exclude`: Attributes to exclude, e.g., `NonControllerAttribute`.
- `Method`: Specifies criteria for method-level entry points.
  - `Accessibility`: Defines accessibility levels, e.g., `public`.
  - `IncludeConstructor`: Whether to include constructors.
  - `Static`: Whether the method should be static.
  - `Attributes`: Specifies attributes to exclude, e.g., `NonActionAttribute`.
- `Parameter`: Specifies criteria for method parameters.
  - `Attributes`: Specifies attributes to exclude, e.g., `FromServicesAttribute`.
  
## Sources
Specify sources to identify where potentially tainted data originates:

```yml  
  TaintSources:
  - Type: Microsoft.AspNetCore.Http.IFormCollection
    IsInterface: true
    Properties:
      - Files
      - Item
  - Type: Microsoft.AspNetCore.Http.HttpRequest
    Properties:
      - Body
      - BodyReader
      - ContentType
      - Cookies
      - Form
      - Headers
      - Host
      - HttpContext
      - Method
      - Path
      - PathBase
      - Protocol
      - Query
      - QueryString
      - RouteValues
      - Scheme
    Methods:
      - ReadFormAsync
```
  
- `Type`: The type of the source.
  - `Microsoft.AspNetCore.Http.IFormCollection`: An interface representing form collections.
    - `IsInterface`: Indicates the type is an interface.
    - `Properties`: Lists properties considered as sources of tainted data.
      - `Files`: Represents form files.
      - `Item`: Represents form items.
  - `Microsoft.AspNetCore.Http.HttpRequest`: Represents HTTP request data.
    - `Properties`: Lists properties of `HttpRequest`.
      - `Body`: The request body.
      - `BodyReader`: The body reader.
      - `ContentType`: The content type.
      - Other properties specify additional sources of tainted data.
    - `Methods`: Lists methods of `HttpRequest`.
      - `ReadFormAsync`: Asynchronously reads form data.

## Sanitizer
Define sanitizers to identify methods that clean tainted data:
 
```yml 
Sanitizers:
  - Type: Microsoft.Security.Application.Encoder
    TaintTypes:
      - SCS0026
    Methods:
      - Name: LdapDistinguishedNameEncode
  - Type: System.Data.IDbCommand
    TaintTypes:
      - SCS0002
    IsAnyStringParameterInConstructorASink: true
    IsInterface: true
    Properties:
      - CommandText

```

- `Type`: The type of the sanitizer.
  - `Microsoft.Security.Application.Encoder`: Represents the `Encoder` class.
    - `TaintTypes`: Specifies applicable analyzer rule IDs.
      - `SCS0026`: An example rule ID.
    - `Methods`: Lists methods that sanitize data.
      - `Name: LdapDistinguishedNameEncode`: Method that encodes LDAP distinguished names.
  - `System.Data.IDbCommand`: Represents database command interfaces.
    - `TaintTypes`: Specifies applicable analyzer rule IDs.
      - `SCS0002`: An example rule ID.
    - `IsAnyStringParameterInConstructorASink`: Indicates if any string parameter in the constructor is a sink.
    - `IsInterface`: Indicates the type is an interface.
    - `Properties`: Lists properties of the type.
      - `CommandText`: Represents the command text property.

## Sinks

Identify sinks to specify where tainted data could cause harm:
```yml
Sinks:
  - Type: System.Data.Linq.DataContext
    TaintTypes:
      - SCS0002
    Methods:
      - Name: ExecuteQuery
        Arguments:
          - query
      - Name: ExecuteCommand
        Arguments:
          - command

```

- `Type`: The type of the sink.
  - `System.Data.Linq.DataContext`: Represents the `DataContext` class.
    - `TaintTypes`: Specifies applicable analyzer rule IDs.
      - `SCS0002`: An example rule ID.
    - `Methods`: Lists methods where tainted data is used.
      - `Name: ExecuteQuery`: Method that executes a query.
        - `Arguments`: Lists arguments of the method.
          - `query`: The query argument.
      - `Name: ExecuteCommand`: Method that executes a command.
        - `Arguments`: Lists arguments of the method.
          - `command`: The command argument.
