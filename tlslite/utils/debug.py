def save_and_return(filename, data):
    print(f"Saving data to {filename}")
    with open(filename, 'wb') as f:
        f.write(data)
    return data
