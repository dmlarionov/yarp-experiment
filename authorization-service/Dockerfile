#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["authorization-service/authorization-service.csproj", "authorization-service/"]
RUN dotnet restore "authorization-service/authorization-service.csproj"
COPY . .
WORKDIR "/src/authorization-service"
RUN dotnet build "authorization-service.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "authorization-service.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "authorization-service.dll"]
