#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["api-gateway/api-gateway.csproj", "api-gateway/"]
COPY ["libraries/session/session.csproj", "libraries/session/"]
RUN dotnet restore "api-gateway/api-gateway.csproj"
COPY . .
WORKDIR "/src/api-gateway"
RUN dotnet build "api-gateway.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "api-gateway.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "api-gateway.dll"]
