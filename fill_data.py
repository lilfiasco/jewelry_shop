from app import db, JewelryType, app


app.app_context().push()

jewelry_type_data = ['Ring', 'Necklace', 'Earring']

jewelry_types = [JewelryType(name=name) for name in jewelry_type_data]
db.session.add_all(jewelry_types)

db.session.commit()
