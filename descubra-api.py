from resources import app
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('--debug', action='store_true')


if __name__ == '__main__':
	app.debug = parser.parse_args().debug
	app.run()